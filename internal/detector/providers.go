package detector

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"

	"github.com/tarasglek/caddy-reverse-bin/detectorschema"
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

func ResolveApp(ctx context.Context, appDir string, env map[string]string) (ResolvedApp, error) {
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
		resolved := ResolvedApp{
			WorkingDirectory: appDir,
			ReverseProxyTo:   stringValue(out.ReverseProxyTo),
			HealthMethod:     cfg.HealthMethod,
			HealthPath:       cfg.HealthPath,
			HealthStatus:     cfg.HealthStatus,
			EnvOverrides:     overrides,
		}
		if out.Executable != nil {
			resolved.Executable = *out.Executable
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
	executable := []string{"deno", "serve", "--watch", "--allow-all", "--host", transport.Host, "--port", transport.Port, "main.ts"}
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

func stringValue(ptr *string) string {
	if ptr == nil {
		return ""
	}
	return *ptr
}
