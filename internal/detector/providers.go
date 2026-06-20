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
	"github.com/tarasglek/reverse-bin-detector/internal/sandbox"
)

type Context struct {
	Context context.Context
	AppDir  string
	Env     map[string]string
	Config  EnvAppConfig
}

type Match struct {
	Provider string
	Root     string
}

type Transport struct {
	ReverseProxyTo string
	Listen         string
	Host           string
	Port           string
	SocketPath     string
	Kind           string
}

type Provider interface {
	Name() string
	Detect(ctx Context) (Match, bool, error)
	Build(ctx Context, match Match, transport Transport) (detectorschema.DetectorOutput, error)
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
	cfg, err := LoadEnvAppConfig(env)
	if err != nil {
		return ResolvedApp{}, err
	}
	dctx := Context{Context: ctx, AppDir: appDir, Env: env, Config: cfg}
	providers := []Provider{explicitProvider{}, denoProvider{}, pythonProvider{}, staticProvider{root: "."}, staticProvider{root: "dist"}}
	for _, provider := range providers {
		match, ok, err := provider.Detect(dctx)
		if err != nil {
			return ResolvedApp{}, err
		}
		if !ok {
			continue
		}
		transport, overrides, err := resolveTransport(appDir, cfg, provider.Name())
		if err != nil {
			return ResolvedApp{}, err
		}
		out, err := provider.Build(dctx, match, transport)
		if err != nil {
			return ResolvedApp{}, err
		}
		envs := buildAppEnvs(appDir, env, overrides, provider.Name())
		resolved := ResolvedApp{
			WorkingDirectory: appDir,
			Envs:             envs,
			ReverseProxyTo:   stringValue(out.ReverseProxyTo),
			HealthMethod:     cfg.HealthMethod,
			HealthPath:       cfg.HealthPath,
			HealthStatus:     cfg.HealthStatus,
			EnvOverrides:     overrides,
		}
		if out.Executable != nil {
			resolved.Executable = *out.Executable
		}
		if !opts.NoRuntimeSandbox {
			resolved.Executable = wrapRuntimeSandbox(resolved.Executable, appDir, transport, resolved.Envs, provider.Name())
		}
		return resolved, nil
	}
	return ResolvedApp{}, fmt.Errorf("No supported entry point (main.ts, executable main.py, index.html, or dist/index.html) found in %s", appDir)
}

type explicitProvider struct{}

func (explicitProvider) Name() string { return "explicit" }
func (explicitProvider) Detect(ctx Context) (Match, bool, error) {
	return Match{Provider: "explicit"}, len(ctx.Config.Command) > 0, nil
}
func (explicitProvider) Build(ctx Context, _ Match, transport Transport) (detectorschema.DetectorOutput, error) {
	executable := append([]string(nil), ctx.Config.Command...)
	return output(executable, ctx.AppDir, transport.ReverseProxyTo), nil
}

type denoProvider struct{}

func (denoProvider) Name() string { return "deno" }
func (denoProvider) Detect(ctx Context) (Match, bool, error) {
	return fileMatch(ctx.AppDir, "main.ts")
}
func (denoProvider) Build(ctx Context, _ Match, transport Transport) (detectorschema.DetectorOutput, error) {
	if transport.Kind == "unix" {
		return detectorschema.DetectorOutput{}, fmt.Errorf("main.ts does not support SOCKET_PATH")
	}
	executable := sandbox.DenoServeArgs(transport.Host, transport.Port, "main.ts")
	return output(executable, ctx.AppDir, transport.ReverseProxyTo), nil
}

type pythonProvider struct{}

func (pythonProvider) Name() string { return "python" }
func (pythonProvider) Detect(ctx Context) (Match, bool, error) {
	path := filepath.Join(ctx.AppDir, "main.py")
	st, err := os.Stat(path)
	if os.IsNotExist(err) {
		return Match{}, false, nil
	}
	if err != nil {
		return Match{}, false, err
	}
	return Match{Provider: "python"}, st.Mode().IsRegular() && st.Mode().Perm()&0o111 != 0, nil
}
func (pythonProvider) Build(ctx Context, _ Match, transport Transport) (detectorschema.DetectorOutput, error) {
	return output([]string{"./main.py"}, ctx.AppDir, transport.ReverseProxyTo), nil
}

type staticProvider struct{ root string }

func (p staticProvider) Name() string { return "static" }
func (p staticProvider) Detect(ctx Context) (Match, bool, error) {
	return fileMatch(ctx.AppDir, filepath.Join(p.root, "index.html"))
}
func (p staticProvider) Build(ctx Context, _ Match, transport Transport) (detectorschema.DetectorOutput, error) {
	if transport.Kind == "unix" {
		return detectorschema.DetectorOutput{}, fmt.Errorf("static file server does not support SOCKET_PATH")
	}
	executable := []string{"reverse-bin-caddy", "file-server", "--listen", transport.Listen, "--root", p.root}
	return output(executable, ctx.AppDir, transport.ReverseProxyTo), nil
}

func fileMatch(appDir, name string) (Match, bool, error) {
	st, err := os.Stat(filepath.Join(appDir, name))
	if os.IsNotExist(err) {
		return Match{}, false, nil
	}
	if err != nil {
		return Match{}, false, err
	}
	return Match{Root: name}, st.Mode().IsRegular(), nil
}

func output(executable []string, workingDir, reverseProxyTo string) detectorschema.DetectorOutput {
	return detectorschema.DetectorOutput{
		Executable:       &executable,
		WorkingDirectory: &workingDir,
		ReverseProxyTo:   &reverseProxyTo,
	}
}

func resolveTransport(appDir string, cfg EnvAppConfig, providerName string) (Transport, map[string]string, error) {
	overrides := map[string]string{}
	if cfg.SocketPath != nil {
		if filepath.IsAbs(*cfg.SocketPath) {
			return Transport{}, nil, fmt.Errorf("Unix socket path must be relative")
		}
		path := filepath.Join(appDir, *cfg.SocketPath)
		return Transport{Kind: "unix", SocketPath: path, ReverseProxyTo: "unix/" + path}, overrides, nil
	}
	if !hasTCPConfig(cfg) && providerName == "python" {
		path := filepath.Join(appDir, "data", "reverse-bin.sock")
		overrides[KeySocketPath] = filepath.Join("data", "reverse-bin.sock")
		return Transport{Kind: "unix", SocketPath: path, ReverseProxyTo: "unix/" + path}, overrides, nil
	}

	host := "127.0.0.1"
	if cfg.ReverseBinHost != nil && *cfg.ReverseBinHost != "" {
		host = *cfg.ReverseBinHost
	}
	port := ""
	allocated := false
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
		allocated = true
	}
	listen := host + ":" + port
	if cfg.Listen != nil && *cfg.Listen == "" {
		overrides[KeyListen] = listen
	}
	if cfg.ReverseBinPort == nil || *cfg.ReverseBinPort == "" {
		overrides[KeyReverseBinHost] = host
		overrides[KeyReverseBinPort] = port
	}
	_ = allocated
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

func wrapRuntimeSandbox(command []string, appDir string, transport Transport, envs []string, providerName string) []string {
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
	if providerName == "deno" {
		wrapped = append(wrapped, "--unrestricted-network")
	} else if transport.Kind == "tcp" && transport.Port != "" {
		wrapped = append(wrapped, "--bind-tcp", transport.Port)
	}
	wrapped = append(wrapped, command...)
	return wrapped
}

func buildAppEnvs(appDir string, appEnv map[string]string, overrides map[string]string, providerName string) []string {
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
	if providerName == "deno" {
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

func stringValue(ptr *string) string {
	if ptr == nil {
		return ""
	}
	return *ptr
}
