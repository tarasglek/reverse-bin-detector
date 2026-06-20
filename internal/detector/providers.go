package detector

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"

	"github.com/tarasglek/caddy-reverse-bin/detectorschema"
)

type appKind string

const (
	explicitApp appKind = "explicit"
	denoApp     appKind = "deno"
	pythonApp   appKind = "python"
	staticApp   appKind = "static"
)

type app struct {
	kind appKind
	root string
	cmd  []string
}

type transport struct {
	kind   string
	proxy  string
	host   string
	port   string
	listen string
}

func ResolveApp(ctx context.Context, appDir string, env map[string]string) (detectorschema.DetectorOutput, error) {
	return ResolveAppWithRuntimeSandbox(ctx, appDir, env, false)
}

func ResolveAppWithRuntimeSandbox(ctx context.Context, appDir string, env map[string]string, runtimeSandbox bool) (detectorschema.DetectorOutput, error) {
	_ = ctx
	cfg, err := LoadEnvAppConfig(env)
	if err != nil {
		return detectorschema.DetectorOutput{}, err
	}
	app, err := detectApp(appDir, cfg)
	if err != nil {
		return detectorschema.DetectorOutput{}, err
	}
	tr, overrides, err := resolveTransport(appDir, cfg, app.kind)
	if err != nil {
		return detectorschema.DetectorOutput{}, err
	}
	cmd, err := commandFor(app, tr)
	if err != nil {
		return detectorschema.DetectorOutput{}, err
	}
	envs := buildAppEnvs(appDir, env, overrides, app.kind)
	if runtimeSandbox {
		cmd = wrapRuntimeSandbox(cmd, appDir, tr, envs, app.kind)
	}
	return schemaOutput(cmd, appDir, envs, tr.proxy, cfg), nil
}

func schemaOutput(cmd []string, appDir string, envs []string, proxy string, cfg EnvAppConfig) detectorschema.DetectorOutput {
	return detectorschema.DetectorOutput{
		Executable:       &cmd,
		WorkingDirectory: &appDir,
		Envs:             &envs,
		ReverseProxyTo:   &proxy,
		HealthMethod:     cfg.HealthMethod,
		HealthPath:       cfg.HealthPath,
		HealthStatus:     cfg.HealthStatus,
	}
}

func detectApp(appDir string, cfg EnvAppConfig) (app, error) {
	if len(cfg.Command) > 0 {
		return app{kind: explicitApp, cmd: append([]string(nil), cfg.Command...)}, nil
	}
	if ok, err := isFile(appDir, "main.ts", false); ok || err != nil {
		return app{kind: denoApp}, err
	}
	if ok, err := isFile(appDir, "main.py", true); ok || err != nil {
		return app{kind: pythonApp}, err
	}
	if ok, err := isFile(appDir, "index.html", false); ok || err != nil {
		return app{kind: staticApp, root: "."}, err
	}
	if ok, err := isFile(appDir, filepath.Join("dist", "index.html"), false); ok || err != nil {
		return app{kind: staticApp, root: "dist"}, err
	}
	return app{}, fmt.Errorf("No supported entry point (main.ts, executable main.py, index.html, or dist/index.html) found in %s", appDir)
}

func commandFor(a app, tr transport) ([]string, error) {
	switch a.kind {
	case explicitApp:
		return append([]string(nil), a.cmd...), nil
	case denoApp:
		if tr.kind == "unix" {
			return nil, fmt.Errorf("main.ts does not support SOCKET_PATH")
		}
		return []string{"deno", "serve", "--watch", "--allow-all", "--host", tr.host, "--port", tr.port, "main.ts"}, nil
	case pythonApp:
		return []string{"./main.py"}, nil
	case staticApp:
		if tr.kind == "unix" {
			return nil, fmt.Errorf("static file server does not support SOCKET_PATH")
		}
		return []string{"reverse-bin-caddy", "file-server", "--listen", tr.listen, "--root", a.root}, nil
	default:
		return nil, fmt.Errorf("unknown app kind %q", a.kind)
	}
}

func isFile(appDir, name string, executable bool) (bool, error) {
	st, err := os.Stat(filepath.Join(appDir, name))
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil || !st.Mode().IsRegular() {
		return false, err
	}
	return !executable || st.Mode().Perm()&0o111 != 0, nil
}

func resolveTransport(appDir string, cfg EnvAppConfig, kind appKind) (transport, map[string]string, error) {
	if cfg.SocketPath != nil {
		if filepath.IsAbs(*cfg.SocketPath) {
			return transport{}, nil, fmt.Errorf("Unix socket path must be relative")
		}
		path := filepath.Join(appDir, *cfg.SocketPath)
		return transport{kind: "unix", proxy: "unix/" + path}, map[string]string{}, nil
	}
	if !hasTCPConfig(cfg) && kind == pythonApp {
		path := filepath.Join(appDir, "data", "reverse-bin.sock")
		return transport{kind: "unix", proxy: "unix/" + path}, map[string]string{KeySocketPath: filepath.Join("data", "reverse-bin.sock")}, nil
	}
	return tcpTransport(cfg)
}

func tcpTransport(cfg EnvAppConfig) (transport, map[string]string, error) {
	overrides := map[string]string{}
	host := "127.0.0.1"
	if cfg.ReverseBinHost != nil && *cfg.ReverseBinHost != "" {
		host = *cfg.ReverseBinHost
	}
	port := ""
	if cfg.Listen != nil {
		var err error
		host, port, err = parseListen(*cfg.Listen)
		if err != nil {
			return transport{}, nil, err
		}
	} else if cfg.ReverseBinPort != nil {
		port = *cfg.ReverseBinPort
	}
	if port == "" {
		var err error
		port, err = allocateFreeTCPPort(host)
		if err != nil {
			return transport{}, nil, err
		}
	}
	listen := host + ":" + port
	if cfg.Listen != nil && *cfg.Listen == "" {
		overrides[KeyListen] = listen
	}
	if cfg.ReverseBinPort == nil || *cfg.ReverseBinPort == "" {
		overrides[KeyReverseBinHost] = host
		overrides[KeyReverseBinPort] = port
	}
	return transport{kind: "tcp", proxy: listen, host: host, port: port, listen: listen}, overrides, nil
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

func parseListen(listen string) (string, string, error) {
	if listen == "" {
		return "127.0.0.1", "8080", nil
	}
	host, port := "127.0.0.1", listen
	for i := len(listen) - 1; i >= 0; i-- {
		if listen[i] == ':' {
			host, port = listen[:i], listen[i+1:]
			break
		}
	}
	if _, err := strconv.Atoi(port); err != nil || port == "" {
		return "", "", fmt.Errorf("Invalid LISTEN port")
	}
	return host, port, nil
}

func wrapRuntimeSandbox(command []string, appDir string, tr transport, envs []string, kind appKind) []string {
	wrapped := []string{"landrun", "--rox", "/bin,/usr,/lib,/lib64,/proc,/sys/fs/cgroup", "--ro", "/etc", "--rw", "/dev"}
	for _, env := range envs {
		wrapped = append(wrapped, "--env", env)
	}
	if st, err := os.Stat(filepath.Join(appDir, "data")); err == nil && st.IsDir() {
		wrapped = append(wrapped, "--rw", filepath.Join(appDir, "data"))
	}
	wrapped = append(wrapped, "--rox", appDir)
	if kind == denoApp {
		wrapped = append(wrapped, "--unrestricted-network")
	} else if tr.kind == "tcp" && tr.port != "" {
		wrapped = append(wrapped, "--bind-tcp", tr.port)
	}
	return append(wrapped, command...)
}

func buildAppEnvs(appDir string, appEnv map[string]string, overrides map[string]string, kind appKind) []string {
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
	if _, ok := merged["HOME"]; !ok {
		dataDir := filepath.Join(appDir, "data")
		if st, err := os.Stat(dataDir); err == nil && st.IsDir() {
			merged["HOME"] = dataDir
		}
	}
	if kind == denoApp {
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
