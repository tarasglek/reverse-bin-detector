package detector

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/tarasglek/caddy-reverse-bin/detectorschema"
	"github.com/tarasglek/reverse-bin-detector/internal/sandbox"
)

var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

const (
	KeyReverseBinCommand      = "REVERSE_BIN_COMMAND"
	KeyListen                 = "LISTEN"
	KeyReverseBinHost         = "REVERSE_BIN_HOST"
	KeyReverseBinPort         = "REVERSE_BIN_PORT"
	KeySocketPath             = "SOCKET_PATH"
	KeyReverseBinHealthMethod = "REVERSE_BIN_HEALTH_METHOD"
	KeyReverseBinHealthPath   = "REVERSE_BIN_HEALTH_PATH"
	KeyReverseBinHealthStatus = "REVERSE_BIN_HEALTH_STATUS"
	KeyReverseBinPublicHost   = "REVERSE_BIN_PUBLIC_HOST"
)

type cliOptions struct {
	noRuntimeSandbox bool
	showVersion      bool
	asApp            bool
	asAppPlan        bool
	writableSource   bool
	publicHost       string
	appDir           string
	command          []string
}

func parseCLIArgs(args []string) (cliOptions, error) {
	var opts cliOptions
	fs := flag.NewFlagSet("reverse-bin-detector", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.BoolVar(&opts.noRuntimeSandbox, "no-runtime-sandbox", false, "run sops and emit the backend command without landrun (tests only)")
	fs.BoolVar(&opts.showVersion, "version", false, "print version and exit")
	fs.BoolVar(&opts.asApp, "as-app", false, "execute command with app runtime sandbox")
	fs.BoolVar(&opts.asAppPlan, "as-app-plan", false, "")
	asAppDev := fs.Bool("as-app-dev", false, "like --as-app, with app source writable (dev sessions)")
	fs.BoolVar(&opts.writableSource, "writable-source", false, "")
	fs.StringVar(&opts.publicHost, "public-host", "", "canonical public host[:port] of the app, served as https://; e.g. app.example.com")
	if err := fs.Parse(args); err != nil {
		return cliOptions{}, err
	}
	if opts.showVersion {
		return opts, nil
	}
	rest := fs.Args()
	modes := 0
	for _, on := range []bool{opts.asApp, *asAppDev, opts.asAppPlan} {
		if on {
			modes++
		}
	}
	if modes > 1 || (opts.writableSource && !opts.asAppPlan) {
		return cliOptions{}, fmt.Errorf("as-app modes cannot be combined")
	}
	if *asAppDev {
		opts.asApp, opts.writableSource = true, true
	}
	if opts.asApp || opts.asAppPlan {
		if len(rest) < 3 || rest[1] != "--" || rest[0] == "" || opts.noRuntimeSandbox {
			return cliOptions{}, fmt.Errorf("usage: reverse-bin-detector [--public-host=HOST] --as-app|--as-app-dev APP_DIR -- COMMAND [ARGS...]")
		}
		opts.command = append([]string(nil), rest[2:]...)
	} else if len(rest) != 1 || opts.writableSource {
		return cliOptions{}, fmt.Errorf("usage: reverse-bin-detector [--no-runtime-sandbox] [--public-host=HOST] APP_DIR\n       reverse-bin-detector [--public-host=HOST] --as-app|--as-app-dev APP_DIR -- COMMAND [ARGS...]")
	}
	appDir, err := filepath.Abs(rest[0])
	if err != nil {
		return cliOptions{}, fmt.Errorf("resolve app directory: %w", err)
	}
	opts.appDir = appDir
	return opts, nil
}

// Run executes the detector CLI.
func Run(ctx context.Context, args []string, stdout io.Writer) error {
	opts, err := parseCLIArgs(args)
	if err != nil {
		return err
	}
	if opts.showVersion {
		_, err := fmt.Fprintf(stdout, "%s %s %s\n", Version, Commit, BuildDate)
		return err
	}
	if opts.asApp {
		return runAsApp(ctx, opts)
	}
	return emitPlan(ctx, opts, stdout)
}

// RunAsAppDev replaces the current process with command inside appDir's
// runtime sandbox with the app source writable, as --as-app-dev does.
func RunAsAppDev(ctx context.Context, appDir string, command []string) error {
	return runAsApp(ctx, cliOptions{appDir: appDir, command: command, writableSource: true})
}

func runAsApp(ctx context.Context, opts cliOptions) error {
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("get executable path: %w", err)
	}
	args := []string{"--as-app-plan", opts.appDir, "--"}
	if opts.writableSource {
		args = append([]string{"--writable-source"}, args...)
	}
	if opts.publicHost != "" {
		args = append([]string{"--public-host=" + opts.publicHost}, args...)
	}
	cmd := exec.CommandContext(ctx, executable, append(args, opts.command...)...)
	// Aliases such as rb-ssh dispatch on argv[0]; the plan helper is always the detector CLI.
	cmd.Args[0] = "reverse-bin-detector"
	cmd.Stderr = os.Stderr
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("generate as-app plan: %w", err)
	}
	plan, err := detectorschema.Parse(output)
	if err != nil {
		return fmt.Errorf("parse as-app plan: %w", err)
	}
	return executeAsAppPlan(plan)
}

// asAppExec is the process image executeAsAppPlan replaces the detector with.
type asAppExec struct {
	path string
	argv []string
	env  []string
	dir  string
}

func prepareAsAppExec(plan *detectorschema.DetectorOutput) (asAppExec, error) {
	if plan == nil || plan.Executable == nil || len(*plan.Executable) == 0 {
		return asAppExec{}, fmt.Errorf("as-app plan missing executable")
	}
	if plan.WorkingDirectory == nil || *plan.WorkingDirectory == "" {
		return asAppExec{}, fmt.Errorf("as-app plan missing working directory")
	}
	path, err := exec.LookPath((*plan.Executable)[0])
	if err != nil {
		return asAppExec{}, fmt.Errorf("as-app plan executable: %w", err)
	}
	env := os.Environ()
	if plan.Envs != nil {
		env = *plan.Envs
	}
	return asAppExec{path: path, argv: *plan.Executable, env: env, dir: *plan.WorkingDirectory}, nil
}

// executeAsAppPlan execs the sandbox instead of supervising it, so signals and
// session hangups reach the sandbox directly and cannot orphan it.
func executeAsAppPlan(plan *detectorschema.DetectorOutput) error {
	exe, err := prepareAsAppExec(plan)
	if err != nil {
		return err
	}
	if err := os.Chdir(exe.dir); err != nil {
		return fmt.Errorf("as-app working directory: %w", err)
	}
	return syscall.Exec(exe.path, exe.argv, exe.env)
}

func emitPlan(ctx context.Context, opts cliOptions, stdout io.Writer) error {
	appDir := opts.appDir
	sandboxed := !opts.noRuntimeSandbox
	if sandboxed {
		if err := sandbox.RequireLandlock(); err != nil {
			return err
		}
	}
	env, err := LoadAppEnv(ctx, appDir, sandboxed)
	if err != nil {
		return err
	}
	if err := applyPublicHost(env, opts.publicHost); err != nil {
		return err
	}
	var out detectorschema.DetectorOutput
	if opts.asAppPlan {
		out, err = resolveApp(ctx, appDir, env, opts.command, true, opts.writableSource)
	} else {
		out, err = ResolveAppWithRuntimeSandbox(ctx, appDir, env, sandboxed)
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(out)
}

type EnvAppConfig struct {
	Command        []string
	Listen         *string
	ReverseBinHost *string
	ReverseBinPort *string
	SocketPath     *string
	HealthMethod   *string
	HealthPath     *string
	HealthStatus   *int
}

func LoadEnvAppConfig(env map[string]string) (EnvAppConfig, error) {
	var cfg EnvAppConfig
	if command, ok := env[KeyReverseBinCommand]; ok && command != "" {
		cfg.Command = []string{"sh", "-c", command}
	}
	cfg.Listen = stringPtrFromMap(env, KeyListen)
	cfg.ReverseBinHost = stringPtrFromMap(env, KeyReverseBinHost)
	cfg.ReverseBinPort = stringPtrFromMap(env, KeyReverseBinPort)
	cfg.SocketPath = stringPtrFromMap(env, KeySocketPath)

	if method, ok := env[KeyReverseBinHealthMethod]; ok {
		method = strings.ToUpper(strings.TrimSpace(method))
		cfg.HealthMethod = &method
	}
	cfg.HealthPath = stringPtrFromMap(env, KeyReverseBinHealthPath)
	if statusText, ok := env[KeyReverseBinHealthStatus]; ok {
		status, err := strconv.Atoi(strings.TrimSpace(statusText))
		if err != nil {
			return EnvAppConfig{}, fmt.Errorf("%s must be an integer", KeyReverseBinHealthStatus)
		}
		if status < 100 || status > 599 {
			return EnvAppConfig{}, fmt.Errorf("%s must be 100 through 599", KeyReverseBinHealthStatus)
		}
		cfg.HealthStatus = &status
	}

	if hasTCPConfig(cfg) && cfg.SocketPath != nil {
		return EnvAppConfig{}, fmt.Errorf("both TCP listener config and SOCKET_PATH are set")
	}
	if cfg.Listen != nil && cfg.ReverseBinPort != nil {
		return EnvAppConfig{}, fmt.Errorf("LISTEN and REVERSE_BIN_PORT cannot both be set")
	}
	if (cfg.HealthMethod == nil) != (cfg.HealthPath == nil) {
		return EnvAppConfig{}, fmt.Errorf("%s and %s must be set together", KeyReverseBinHealthMethod, KeyReverseBinHealthPath)
	}
	if cfg.HealthStatus != nil && (cfg.HealthMethod == nil || cfg.HealthPath == nil) {
		return EnvAppConfig{}, fmt.Errorf("%s requires %s and %s", KeyReverseBinHealthStatus, KeyReverseBinHealthMethod, KeyReverseBinHealthPath)
	}
	return cfg, nil
}

func stringPtrFromMap(env map[string]string, key string) *string {
	value, ok := env[key]
	if !ok {
		return nil
	}
	return &value
}

func hasTCPConfig(cfg EnvAppConfig) bool {
	return cfg.Listen != nil || cfg.ReverseBinHost != nil || cfg.ReverseBinPort != nil
}

var ErrMultipleEnvSources = errors.New("multiple env sources")

// LoadAppEnv reads APP/.env or decrypts APP/secrets.enc.json. Both are read
// through os.Root, so a tenant's symlink to another app's files is an error.
// sandboxed runs sops under landrun.
func LoadAppEnv(ctx context.Context, appDir string, sandboxed bool) (map[string]string, error) {
	root, err := os.OpenRoot(appDir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	dotEnv, err := readOptional(root, ".env")
	if err != nil {
		return nil, err
	}
	secrets, err := readOptional(root, "secrets.enc.json")
	if err != nil {
		return nil, err
	}
	switch {
	case dotEnv != nil && secrets != nil:
		return nil, fmt.Errorf("%w: cannot use both .env and secrets.enc.json", ErrMultipleEnvSources)
	case dotEnv != nil:
		return parseDotEnv(string(dotEnv)), nil
	case secrets != nil:
		dotenv, err := decryptSOPS(ctx, secrets, sandboxed)
		if err != nil {
			return nil, fmt.Errorf("decrypt secrets.enc.json: %w", err)
		}
		return parseDotEnv(dotenv), nil
	}
	return map[string]string{}, nil
}

// readOptional returns nil for a missing file.
func readOptional(root *os.Root, name string) ([]byte, error) {
	data, err := root.ReadFile(name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	return data, err
}

// decryptSOPS feeds ciphertext to sops on stdin, so sops opens no app path.
func decryptSOPS(ctx context.Context, ciphertext []byte, sandboxed bool) (string, error) {
	sopsPath, err := exec.LookPath("sops")
	if err != nil {
		return "", err
	}
	argv := []string{sopsPath, "decrypt", "--input-type", "json", "--output-type", "dotenv"}
	if sandboxed {
		key := os.Getenv("SOPS_AGE_KEY_FILE")
		var names []string
		if key != "" {
			names = []string{"SOPS_AGE_KEY_FILE"}
		}
		argv = sandbox.Command(sandbox.SOPSPolicy(sopsPath, key), names, argv)
	}
	// Tenant metadata naming KMS makes sops retry for ~13 s even with every
	// connect denied; Caddy waits for the plan.
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Stdin = bytes.NewReader(ciphertext)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.Output()
	if ctx.Err() != nil {
		return "", fmt.Errorf("sops timed out after 5s; does secrets.enc.json name non-age keys? %w", ctx.Err())
	}
	if err != nil {
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return "", fmt.Errorf("%w: %s", err, msg)
		}
		return "", err
	}
	return string(stdout), nil
}

func parseDotEnv(content string) map[string]string {
	env := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, value, ok := strings.Cut(line, "=")
		if !ok || name == "" {
			continue
		}
		env[name] = trimEnvValue(value)
	}
	return env
}

func trimEnvValue(value string) string {
	value = strings.TrimSpace(value)
	if len(value) >= 2 {
		quote := value[0]
		if (quote == '\'' || quote == '"') && value[len(value)-1] == quote {
			return value[1 : len(value)-1]
		}
	}
	return value
}

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
	kind      string
	proxy     string
	host      string
	port      string
	listen    string
	socketDir string
}

func ResolveApp(ctx context.Context, appDir string, env map[string]string) (detectorschema.DetectorOutput, error) {
	return ResolveAppWithRuntimeSandbox(ctx, appDir, env, false)
}

func ResolveAppWithRuntimeSandbox(ctx context.Context, appDir string, env map[string]string, runtimeSandbox bool) (detectorschema.DetectorOutput, error) {
	return resolveApp(ctx, appDir, env, nil, runtimeSandbox, false)
}

func resolveApp(ctx context.Context, appDir string, env map[string]string, customCommand []string, runtimeSandbox, writableSource bool) (detectorschema.DetectorOutput, error) {
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
	cmd := append([]string(nil), customCommand...)
	if cmd == nil {
		cmd, err = commandFor(app, tr)
		if err != nil {
			return detectorschema.DetectorOutput{}, err
		}
	}
	envs, names := buildAppEnvs(appDir, env, overrides, app.kind)
	if runtimeSandbox {
		policy, err := sandbox.RuntimePolicy(appDir, app.kind == staticApp, tr.socketDir)
		if err != nil {
			return detectorschema.DetectorOutput{}, err
		}
		if writableSource {
			policy = policy.WithWritable(appDir)
		}
		cmd = wrapPIDNamespace(sandbox.Command(policy, names, cmd))
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
		if tr.kind != "unix" {
			return nil, fmt.Errorf("static file server only supports Unix sockets")
		}
		path := strings.TrimPrefix(tr.proxy, "unix/")
		return []string{"reverse-bin-caddy", "file-server", "--listen", "unix//" + path, "--root", a.root}, nil
	default:
		return nil, fmt.Errorf("unknown app kind %q", a.kind)
	}
}

// isFile stats through os.Root: a symlink out of appDir is an error.
func isFile(appDir, name string, executable bool) (bool, error) {
	root, err := os.OpenRoot(appDir)
	if err != nil {
		return false, err
	}
	defer root.Close()
	st, err := root.Stat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil || !st.Mode().IsRegular() {
		return false, err
	}
	return !executable || st.Mode().Perm()&0o111 != 0, nil
}

func resolveTransport(appDir string, cfg EnvAppConfig, kind appKind) (transport, map[string]string, error) {
	if kind == staticApp {
		if cfg.SocketPath != nil || hasTCPConfig(cfg) {
			return transport{}, nil, fmt.Errorf("static file server only supports reverse-bin-managed Unix sockets")
		}
		dir := staticRuntimeDir(appDir)
		path := filepath.Join(dir, "reverse-bin.sock")
		return transport{kind: "unix", proxy: "unix/" + path, socketDir: dir}, map[string]string{}, nil
	}
	if cfg.SocketPath != nil {
		tr, err := appSocket(appDir, *cfg.SocketPath)
		return tr, map[string]string{}, err
	}
	if !hasTCPConfig(cfg) && kind == pythonApp {
		rel := filepath.Join("data", "reverse-bin.sock")
		tr, err := appSocket(appDir, rel)
		return tr, map[string]string{KeySocketPath: rel}, err
	}
	return tcpTransport(cfg)
}

// appSocket rejects socket paths that leave appDir, by .. or by a symlinked
// directory: Caddy, outside the sandbox, deletes the socket before launch.
func appSocket(appDir, rel string) (transport, error) {
	if !filepath.IsLocal(rel) {
		return transport{}, fmt.Errorf("Unix socket path must be relative and inside the app directory")
	}
	if dir := filepath.Dir(rel); dir != "." {
		root, err := os.OpenRoot(appDir)
		if err != nil {
			return transport{}, err
		}
		defer root.Close()
		if _, err := root.Stat(dir); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return transport{}, fmt.Errorf("Unix socket directory: %w", err)
		}
	}
	return transport{kind: "unix", proxy: "unix/" + filepath.Join(appDir, rel)}, nil
}

func staticRuntimeDir(appDir string) string {
	sum := sha256.Sum256([]byte(filepath.Clean(appDir)))
	return filepath.Join("/run/reverse-bin/static-apps", "app-"+hex.EncodeToString(sum[:])[:16])
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

func wrapPIDNamespace(command []string) []string {
	wrapped := []string{"unshare", "--map-current-user", "--pid", "--fork", "--mount-proc", "--ipc", "--uts", "--kill-child", "--"}
	return append(wrapped, command...)
}

// buildAppEnvs returns the app environment as sorted NAME=VALUE entries and
// the matching names.
func buildAppEnvs(appDir string, appEnv map[string]string, overrides map[string]string, kind appKind) ([]string, []string) {
	merged := make(map[string]string, len(appEnv)+len(overrides)+3)
	maps.Copy(merged, appEnv)
	maps.Copy(merged, overrides)
	if _, ok := merged["PATH"]; !ok {
		if path := os.Getenv("PATH"); path != "" {
			merged["PATH"] = path
		}
	}
	if _, ok := merged["HOME"]; !ok {
		merged["HOME"] = filepath.Join(appDir, "data")
	}
	if _, ok := merged["TMPDIR"]; !ok {
		merged["TMPDIR"] = "data"
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
	return envs, keys
}
