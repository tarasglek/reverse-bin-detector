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
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

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
)

type cliOptions struct {
	allowUnsafeNoLandlock bool
	noRuntimeSandbox      bool
	showVersion           bool
	sandboxExec           bool
	sandboxExecPlan       bool
	appDir                string
	command               []string
}

func parseCLIArgs(args []string) (cliOptions, error) {
	var opts cliOptions
	fs := flag.NewFlagSet("reverse-bin-detector", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.BoolVar(&opts.allowUnsafeNoLandlock, "allow-unsafe-no-landlock", false, "disable detection Landlock sandbox")
	fs.BoolVar(&opts.noRuntimeSandbox, "no-runtime-sandbox", false, "emit backend command without runtime sandbox wrapper")
	fs.BoolVar(&opts.showVersion, "version", false, "print version and exit")
	fs.BoolVar(&opts.sandboxExec, "as-app", false, "execute command with app runtime sandbox")
	fs.BoolVar(&opts.sandboxExecPlan, "as-app-plan", false, "")
	if err := fs.Parse(args); err != nil {
		return cliOptions{}, err
	}
	if opts.showVersion {
		return opts, nil
	}
	rest := fs.Args()
	if opts.sandboxExec && opts.sandboxExecPlan {
		return cliOptions{}, fmt.Errorf("sandbox exec modes cannot be combined")
	}
	if opts.sandboxExec || opts.sandboxExecPlan {
		if len(rest) < 3 || rest[1] != "--" || rest[0] == "" || opts.noRuntimeSandbox {
			return cliOptions{}, fmt.Errorf("usage: reverse-bin-detector --as-app APP_DIR -- COMMAND [ARGS...]")
		}
		opts.appDir = rest[0]
		opts.command = append([]string(nil), rest[2:]...)
		return opts, nil
	}
	if len(rest) != 1 {
		return cliOptions{}, fmt.Errorf("usage: reverse-bin-detector [--allow-unsafe-no-landlock] APP_DIR\n       reverse-bin-detector --as-app APP_DIR -- COMMAND [ARGS...]")
	}
	opts.appDir = rest[0]
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
	if opts.sandboxExec {
		return runSandboxExec(ctx, opts)
	}
	return emitPlan(ctx, opts, stdout)
}

func runSandboxExec(ctx context.Context, opts cliOptions) error {
	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("get executable path: %w", err)
	}
	plan, err := requestSandboxExecPlan(ctx, execPath, opts)
	if err != nil {
		return err
	}
	if plan.WorkingDirectory == nil || *plan.WorkingDirectory == "" {
		return fmt.Errorf("sandbox exec plan missing working directory")
	}
	if len(*plan.Executable) == 0 {
		return fmt.Errorf("sandbox exec plan missing executable")
	}
	if err := os.Chdir(*plan.WorkingDirectory); err != nil {
		return fmt.Errorf("change to working directory %s: %w", *plan.WorkingDirectory, err)
	}
	cmd := exec.Command((*plan.Executable)[0], (*plan.Executable)[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if plan.Envs != nil {
		cmd.Env = *plan.Envs
	}
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		return fmt.Errorf("execute sandboxed command: %w", err)
	}
	return nil
}

func requestSandboxExecPlan(ctx context.Context, executable string, opts cliOptions) (*detectorschema.DetectorOutput, error) {
	args := make([]string, 0, len(opts.command)+5)
	if opts.allowUnsafeNoLandlock {
		args = append(args, "--allow-unsafe-no-landlock")
	}
	if opts.noRuntimeSandbox {
		args = append(args, "--no-runtime-sandbox")
	}
	args = append(args, "--as-app-plan", opts.appDir, "--")
	args = append(args, opts.command...)
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.Stderr = os.Stderr
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("generate sandbox exec plan: %w", err)
	}
	plan, err := detectorschema.Parse(output)
	if err != nil {
		return nil, fmt.Errorf("parse sandbox exec plan: %w", err)
	}
	return plan, nil
}

func emitPlan(ctx context.Context, opts cliOptions, stdout io.Writer) error {
	appDir := opts.appDir
	if !opts.allowUnsafeNoLandlock {
		if err := sandbox.ApplyDetection(appDir, environMap(os.Environ()), sandbox.LandlockOptions{}); err != nil {
			return err
		}
	}
	env, err := LoadAppEnv(ctx, appDir)
	if err != nil {
		return err
	}
	var out detectorschema.DetectorOutput
	if opts.sandboxExecPlan {
		out, err = ResolveAppWithCustomCommand(ctx, appDir, env, opts.command, !opts.noRuntimeSandbox)
	} else {
		out, err = ResolveAppWithRuntimeSandbox(ctx, appDir, env, !opts.noRuntimeSandbox)
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(out)
}

func environMap(environ []string) map[string]string {
	env := make(map[string]string, len(environ))
	for _, entry := range environ {
		name, value, ok := strings.Cut(entry, "=")
		if ok {
			env[name] = value
		}
	}
	return env
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

func LoadAppEnv(ctx context.Context, appDir string) (map[string]string, error) {
	dotEnvPath := filepath.Join(appDir, ".env")
	secretsPath := filepath.Join(appDir, "secrets.enc.json")
	hasDotEnv, err := fileExists(dotEnvPath)
	if err != nil {
		return nil, err
	}
	hasSecrets, err := fileExists(secretsPath)
	if err != nil {
		return nil, err
	}
	if hasDotEnv && hasSecrets {
		return nil, fmt.Errorf("%w: cannot use both .env and secrets.enc.json", ErrMultipleEnvSources)
	}
	if !hasDotEnv && !hasSecrets {
		return map[string]string{}, nil
	}

	if hasDotEnv {
		data, err := os.ReadFile(dotEnvPath)
		if err != nil {
			return nil, err
		}
		return parseDotEnv(string(data)), nil
	}
	dotenv, err := decryptSOPS(ctx, secretsPath)
	if err != nil {
		return nil, fmt.Errorf("decrypt secrets.enc.json: %w", err)
	}
	return parseDotEnv(dotenv), nil
}

func decryptSOPS(ctx context.Context, path string) (string, error) {
	sopsPath, err := exec.LookPath("sops")
	if err != nil {
		return "", err
	}
	cmd := exec.CommandContext(ctx, sopsPath, "--decrypt", "--input-type", "json", "--output-type", "dotenv", path)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.Output()
	if err != nil {
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return "", fmt.Errorf("%w: %s", err, msg)
		}
		return "", err
	}
	return string(stdout), nil
}

func fileExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
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
	return resolveApp(ctx, appDir, env, nil, runtimeSandbox)
}

func ResolveAppWithCustomCommand(ctx context.Context, appDir string, env map[string]string, command []string, runtimeSandbox bool) (detectorschema.DetectorOutput, error) {
	if len(command) == 0 {
		return detectorschema.DetectorOutput{}, fmt.Errorf("command is required")
	}
	return resolveApp(ctx, appDir, env, command, runtimeSandbox)
}

func resolveApp(ctx context.Context, appDir string, env map[string]string, customCommand []string, runtimeSandbox bool) (detectorschema.DetectorOutput, error) {
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
	envs := buildAppEnvs(appDir, env, overrides, app.kind)
	if customCommand != nil {
		envs = defaultPlanHome(envs, appDir)
	}
	if runtimeSandbox {
		cmd = wrapPIDNamespace(wrapRuntimeSandbox(cmd, appDir, tr, envs, app.kind))
	}
	return schemaOutput(cmd, appDir, envs, tr.proxy, cfg), nil
}

// defaultPlanHome guarantees HOME in the plan environment so interactive
// shells cannot fall back to the caller's password-database home directory
// and source its rc files. HOME is always the app data dir, matching
// production; warn when data/ does not exist yet.
func defaultPlanHome(envs []string, appDir string) []string {
	for _, entry := range envs {
		if strings.HasPrefix(entry, "HOME=") {
			return envs
		}
	}
	dataDir := filepath.Join(appDir, "data")
	if _, err := os.Stat(dataDir); err != nil {
		fmt.Fprintf(os.Stderr, "warning: %s does not exist; create it with mkdir -p %s (HOME points there anyway)\n", dataDir, dataDir)
	}
	return append(envs, "HOME="+dataDir)
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
	if kind == staticApp {
		if cfg.SocketPath != nil || hasTCPConfig(cfg) {
			return transport{}, nil, fmt.Errorf("static file server only supports reverse-bin-managed Unix sockets")
		}
		dir := staticRuntimeDir(appDir)
		path := filepath.Join(dir, "reverse-bin.sock")
		return transport{kind: "unix", proxy: "unix/" + path, socketDir: dir}, map[string]string{}, nil
	}
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

func wrapRuntimeSandbox(command []string, appDir string, tr transport, envs []string, kind appKind) []string {
	wrapped := []string{"landrun", "--rox", "/bin,/usr,/lib,/lib64,/proc,/sys/fs/cgroup", "--ro", "/etc", "--rw", "/dev"}
	for _, env := range envs {
		wrapped = append(wrapped, "--env", env)
	}
	if st, err := os.Stat(filepath.Join(appDir, "data")); kind != staticApp && err == nil && st.IsDir() {
		wrapped = append(wrapped, "--rw", filepath.Join(appDir, "data"))
	}
	if tr.socketDir != "" {
		wrapped = append(wrapped, "--rw", tr.socketDir)
	}
	wrapped = append(wrapped, "--rox", appDir)
	if kind != staticApp {
		wrapped = append(wrapped, "--ro", "/sys", "--unrestricted-network")
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
	return envs
}
