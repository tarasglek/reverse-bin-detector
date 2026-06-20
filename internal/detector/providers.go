package detector

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
)

type AppKind string

const (
	AppExplicit AppKind = "explicit"
	AppDeno     AppKind = "deno"
	AppPython   AppKind = "python"
	AppStatic   AppKind = "static"
)

type App struct {
	Kind    AppKind
	Root    string
	Command []string
}

type Transport struct {
	ReverseProxyTo string
	Listen         string
	Host           string
	Port           string
	SocketPath     string
	Kind           string
}

type ResolvedApp struct {
	Executable       []string
	WorkingDirectory string
	Envs             []string
	ReverseProxyTo   string
	HealthMethod     *string
	HealthPath       *string
	HealthStatus     *int
	EnvOverrides     map[string]string
}

type Options struct {
	NoRuntimeSandbox bool
}

func ResolveApp(ctx context.Context, appDir string, env map[string]string) (ResolvedApp, error) {
	return ResolveAppWithOptions(ctx, appDir, env, Options{NoRuntimeSandbox: true})
}

func ResolveAppWithOptions(ctx context.Context, appDir string, env map[string]string, opts Options) (ResolvedApp, error) {
	_ = ctx
	cfg, err := LoadEnvAppConfig(env)
	if err != nil {
		return ResolvedApp{}, err
	}
	app, err := detectApp(appDir, cfg)
	if err != nil {
		return ResolvedApp{}, err
	}
	transport, overrides, err := resolveTransport(appDir, cfg, app.Kind)
	if err != nil {
		return ResolvedApp{}, err
	}
	cmd, err := commandFor(app, transport)
	if err != nil {
		return ResolvedApp{}, err
	}
	envs := buildAppEnvs(appDir, env, overrides, app.Kind)
	if !opts.NoRuntimeSandbox {
		cmd = wrapRuntimeSandbox(cmd, appDir, transport, envs, app.Kind)
	}
	return ResolvedApp{
		Executable:       cmd,
		WorkingDirectory: appDir,
		Envs:             envs,
		ReverseProxyTo:   transport.ReverseProxyTo,
		HealthMethod:     cfg.HealthMethod,
		HealthPath:       cfg.HealthPath,
		HealthStatus:     cfg.HealthStatus,
		EnvOverrides:     overrides,
	}, nil
}

func detectApp(appDir string, cfg EnvAppConfig) (App, error) {
	if len(cfg.Command) > 0 {
		return App{Kind: AppExplicit, Command: append([]string(nil), cfg.Command...)}, nil
	}
	if ok, err := regularFile(filepath.Join(appDir, "main.ts")); ok || err != nil {
		return App{Kind: AppDeno, Root: "."}, err
	}
	if ok, err := executableFile(filepath.Join(appDir, "main.py")); ok || err != nil {
		return App{Kind: AppPython, Root: "."}, err
	}
	if ok, err := regularFile(filepath.Join(appDir, "index.html")); ok || err != nil {
		return App{Kind: AppStatic, Root: "."}, err
	}
	if ok, err := regularFile(filepath.Join(appDir, "dist", "index.html")); ok || err != nil {
		return App{Kind: AppStatic, Root: "dist"}, err
	}
	return App{}, fmt.Errorf("No supported entry point (main.ts, executable main.py, index.html, or dist/index.html) found in %s", appDir)
}

func commandFor(app App, transport Transport) ([]string, error) {
	switch app.Kind {
	case AppExplicit:
		return append([]string(nil), app.Command...), nil
	case AppDeno:
		if transport.Kind == "unix" {
			return nil, fmt.Errorf("main.ts does not support SOCKET_PATH")
		}
		return []string{"deno", "serve", "--watch", "--allow-all", "--host", transport.Host, "--port", transport.Port, "main.ts"}, nil
	case AppPython:
		return []string{"./main.py"}, nil
	case AppStatic:
		if transport.Kind == "unix" {
			return nil, fmt.Errorf("static file server does not support SOCKET_PATH")
		}
		return []string{"reverse-bin-caddy", "file-server", "--listen", transport.Listen, "--root", app.Root}, nil
	default:
		return nil, fmt.Errorf("unknown app kind %q", app.Kind)
	}
}

func regularFile(path string) (bool, error) {
	st, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return st.Mode().IsRegular(), nil
}

func executableFile(path string) (bool, error) {
	st, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return st.Mode().IsRegular() && st.Mode().Perm()&0o111 != 0, nil
}

func resolveTransport(appDir string, cfg EnvAppConfig, kind AppKind) (Transport, map[string]string, error) {
	if cfg.SocketPath != nil {
		return configuredUnixTransport(appDir, *cfg.SocketPath)
	}
	if !hasTCPConfig(cfg) && kind == AppPython {
		return defaultPythonUnixTransport(appDir), map[string]string{KeySocketPath: filepath.Join("data", "reverse-bin.sock")}, nil
	}
	return tcpTransport(cfg)
}

func configuredUnixTransport(appDir, socketPath string) (Transport, map[string]string, error) {
	if filepath.IsAbs(socketPath) {
		return Transport{}, nil, fmt.Errorf("Unix socket path must be relative")
	}
	path := filepath.Join(appDir, socketPath)
	return Transport{Kind: "unix", SocketPath: path, ReverseProxyTo: "unix/" + path}, map[string]string{}, nil
}

func defaultPythonUnixTransport(appDir string) Transport {
	path := filepath.Join(appDir, "data", "reverse-bin.sock")
	return Transport{Kind: "unix", SocketPath: path, ReverseProxyTo: "unix/" + path}
}

func tcpTransport(cfg EnvAppConfig) (Transport, map[string]string, error) {
	overrides := map[string]string{}
	host := "127.0.0.1"
	if cfg.ReverseBinHost != nil && *cfg.ReverseBinHost != "" {
		host = *cfg.ReverseBinHost
	}

	port := ""
	if cfg.Listen != nil {
		listenHost, listenPort, err := parseListen(*cfg.Listen)
		if err != nil {
			return Transport{}, nil, err
		}
		host, port = listenHost, listenPort
	} else if cfg.ReverseBinPort != nil {
		port = *cfg.ReverseBinPort
	}
	if port == "" {
		freePort, err := allocateFreeTCPPort(host)
		if err != nil {
			return Transport{}, nil, err
		}
		port = freePort
	}

	listen := host + ":" + port
	if cfg.Listen != nil && *cfg.Listen == "" {
		overrides[KeyListen] = listen
	}
	if cfg.ReverseBinPort == nil || *cfg.ReverseBinPort == "" {
		overrides[KeyReverseBinHost] = host
		overrides[KeyReverseBinPort] = port
	}
	return Transport{Kind: "tcp", Host: host, Port: port, Listen: listen, ReverseProxyTo: listen}, overrides, nil
}

func allocateFreeTCPPort(host string) (string, error) {
	ln, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		return "", fmt.Errorf("allocate free TCP port: %w", err)
	}
	defer ln.Close()
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		return "", fmt.Errorf("parse allocated TCP port: %w", err)
	}
	return port, nil
}

func parseListen(listen string) (host string, port string, err error) {
	if listen == "" {
		return "127.0.0.1", "8080", nil
	}
	lastColon := -1
	for i := len(listen) - 1; i >= 0; i-- {
		if listen[i] == ':' {
			lastColon = i
			break
		}
	}
	if lastColon >= 0 {
		host = listen[:lastColon]
		port = listen[lastColon+1:]
	} else {
		host = "127.0.0.1"
		port = listen
	}
	if _, convErr := strconv.Atoi(port); convErr != nil || port == "" {
		return "", "", fmt.Errorf("Invalid LISTEN port")
	}
	return host, port, nil
}

func wrapRuntimeSandbox(command []string, appDir string, transport Transport, envs []string, kind AppKind) []string {
	if len(command) == 0 {
		return command
	}
	wrapped := []string{"landrun", "--rox", "/bin,/usr,/lib,/lib64,/proc,/sys/fs/cgroup", "--ro", "/etc", "--rw", "/dev"}
	for _, env := range envs {
		wrapped = append(wrapped, "--env", env)
	}
	if st, err := os.Stat(filepath.Join(appDir, "data")); err == nil && st.IsDir() {
		wrapped = append(wrapped, "--rw", filepath.Join(appDir, "data"))
	}
	wrapped = append(wrapped, "--rox", appDir)
	if kind == AppDeno {
		wrapped = append(wrapped, "--unrestricted-network")
	} else if transport.Kind == "tcp" && transport.Port != "" {
		wrapped = append(wrapped, "--bind-tcp", transport.Port)
	}
	wrapped = append(wrapped, command...)
	return wrapped
}

func buildAppEnvs(appDir string, appEnv map[string]string, overrides map[string]string, kind AppKind) []string {
	merged := make(map[string]string, len(appEnv)+len(overrides)+3)
	for key, value := range appEnv {
		merged[key] = value
	}
	for key, value := range overrides {
		merged[key] = value
	}
	if _, ok := merged["PATH"]; !ok {
		if path := os.Getenv("PATH"); path != "" {
			merged["PATH"] = path
		}
	}
	dataDir := filepath.Join(appDir, "data")
	if _, ok := merged["HOME"]; !ok {
		if st, err := os.Stat(dataDir); err == nil && st.IsDir() {
			merged["HOME"] = dataDir
		}
	}
	if kind == AppDeno {
		merged["DENO_NO_UPDATE_CHECK"] = "1"
	}

	keys := make([]string, 0, len(merged))
	for key := range merged {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	envs := make([]string, 0, len(keys))
	for _, key := range keys {
		envs = append(envs, key+"="+merged[key])
	}
	return envs
}
