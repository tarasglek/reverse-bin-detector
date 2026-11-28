package main

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// App is reverse-bin's App: exactly what the plugin runs.
type App struct {
	Executable       []string `json:"executable"`
	WorkingDirectory string   `json:"working_directory"`
	Envs             []string `json:"envs"` // sorted KEY=value
	ReverseProxyTo   string   `json:"reverse_proxy_to"`
	HealthMethod     string   `json:"health_method,omitempty"`
	HealthPath       string   `json:"health_path,omitempty"`
	HealthStatus     int      `json:"health_status,omitempty"`
}

// Keys an app sets in .env or secrets.enc.json. Any other REVERSE_BIN_* key
// is an error, so a misspelt one fails loudly.
const (
	KeyReverseBinCommand      = "REVERSE_BIN_COMMAND"
	KeyReverseBinHost         = "REVERSE_BIN_HOST"
	KeyReverseBinPort         = "REVERSE_BIN_PORT"
	KeySocketPath             = "SOCKET_PATH"
	KeyReverseBinHealthMethod = "REVERSE_BIN_HEALTH_METHOD"
	KeyReverseBinHealthPath   = "REVERSE_BIN_HEALTH_PATH"
	KeyReverseBinHealthStatus = "REVERSE_BIN_HEALTH_STATUS"
	KeyReverseBinPublicHost   = "REVERSE_BIN_PUBLIC_HOST"
	KeyReverseBinBindTCP      = "REVERSE_BIN_BIND_TCP"
)

var knownKeys = []string{KeyReverseBinCommand, KeyReverseBinHost, KeyReverseBinPort, KeyReverseBinHealthMethod,
	KeyReverseBinHealthPath, KeyReverseBinHealthStatus, KeyReverseBinPublicHost, KeyReverseBinBindTCP}

type kind string

const (
	explicitApp kind = "explicit"
	denoApp     kind = "deno"
	staticApp   kind = "static"
)

// preSandboxEnv is glibc's UNSECURE_ENVVARS (sysdeps/generic/unsecvars.h,
// glibc 2.41), the variables it drops for setuid programs, without LD_*
// (refused by prefix) and without those an app sets for itself that nothing
// before the sandbox acts on harmfully: TMPDIR (the detector's own default),
// TZDIR, the resolver's HOSTALIASES, LOCALDOMAIN, RES_OPTIONS and
// RESOLV_HOST_CONF, and the malloc tunables, which only size unshare's
// allocator. Before the sandbox only unshare runs glibc with the app's env
// (landrun is static Go); it calls setlocale, gettext and getpwuid (so NSS
// loads, hence NIS_PATH), but no resolver, time-zone or temporary-file
// function.
var preSandboxEnv = []string{
	"GCONV_PATH", "GETCONF_DIR", "GLIBC_TUNABLES", "LOCPATH", "MALLOC_TRACE", "NIS_PATH", "NLSPATH",
}

// plan builds the App for appDir. A non-nil command replaces the app's own
// (--as-app); writable makes the source writable (--as-app-dev).
func plan(ctx context.Context, appDir, publicHost string, sandboxed bool, command []string, writable bool) (App, error) {
	if sandboxed {
		if err := RequireLandlock(); err != nil {
			return App{}, err
		}
	}
	env, err := loadEnv(ctx, appDir, sandboxed)
	if err != nil {
		return App{}, err
	}
	for k := range env {
		if strings.HasPrefix(k, "REVERSE_BIN_") && !slices.Contains(knownKeys, k) {
			return App{}, fmt.Errorf("unknown key %s; known: %s", k, strings.Join(knownKeys, ", "))
		}
		// unshare and landrun start with the app's env, before the sandbox
		// exists: the dynamic loader and glibc would act on these there.
		if strings.HasPrefix(k, "LD_") || slices.Contains(preSandboxEnv, k) {
			return App{}, fmt.Errorf("%s would act before the sandbox; set it in the launch command instead", k)
		}
	}
	if err := setPublicHost(env, publicHost); err != nil {
		return App{}, err
	}
	k, root, err := detectKind(appDir, env)
	if err != nil {
		return App{}, err
	}
	a := App{WorkingDirectory: appDir, HealthPath: "/", HealthMethod: strings.ToUpper(env[KeyReverseBinHealthMethod])}
	if path, ok := env[KeyReverseBinHealthPath]; ok {
		a.HealthPath = path // empty: ready once it accepts a connection
	}
	if s := env[KeyReverseBinHealthStatus]; s != "" {
		if a.HealthStatus, err = strconv.Atoi(strings.TrimSuffix(s, "xx")); err != nil {
			return App{}, fmt.Errorf("%s: want a code like 200 or a class like 2xx, got %q", KeyReverseBinHealthStatus, s)
		}
	}
	_, hasHost := env[KeyReverseBinHost]
	_, hasPort := env[KeyReverseBinPort]
	rel, unix := env[KeySocketPath]
	if unix && (hasHost || hasPort) {
		return App{}, fmt.Errorf("both TCP listener config and %s are set", KeySocketPath)
	}
	bindTCP, err := parseBindTCP(env[KeyReverseBinBindTCP])
	if err != nil {
		return App{}, err
	}
	var socketDir string
	var fallback []string // the app's own command
	switch {
	case k == staticApp:
		if unix || hasHost || hasPort || len(bindTCP) > 0 {
			return App{}, fmt.Errorf("static file server only supports reverse-bin-managed Unix sockets")
		}
		// The static sandbox has no network grant, so it serves a unix socket
		// in a directory of its own. Caddy's file server removes a stale one.
		sum := sha256.Sum256([]byte(filepath.Clean(appDir)))
		socketDir = filepath.Join(staticRoot, "app-"+hex.EncodeToString(sum[:])[:16])
		if err := os.MkdirAll(socketDir, 0o700); err != nil {
			return App{}, err
		}
		a.ReverseProxyTo = "unix/" + filepath.Join(socketDir, "reverse-bin.sock")
		fallback = []string{"reverse-bin-caddy", "file-server", "--listen", "unix/" + a.ReverseProxyTo[5:], "--root", root}
	case unix:
		if k == denoApp {
			return App{}, fmt.Errorf("main.ts does not support %s", KeySocketPath)
		}
		path, err := appSocket(appDir, rel)
		if err != nil {
			return App{}, err
		}
		a.ReverseProxyTo = "unix/" + path
		// Removed inside the launched command: after reverse-bin's
		// single-instance claim, so never another copy's live socket.
		fallback = append([]string{"sh", "-c", `rm -f -- "$SOCKET_PATH" && exec "$@"`, "sh"}, kindCommand(k, env)...)
	default:
		host := cmp.Or(env[KeyReverseBinHost], "127.0.0.1")
		// Caddy dials this address with the visitor's request: only loopback.
		if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() && !ip.IsUnspecified() {
			return App{}, fmt.Errorf("%s=%s: want a loopback or wildcard IP", KeyReverseBinHost, host)
		}
		port := env[KeyReverseBinPort]
		if port == "" {
			if port, err = freePort(host); err != nil {
				return App{}, err
			}
		}
		env[KeyReverseBinHost], env[KeyReverseBinPort] = host, port
		dialHost := host
		if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
			dialHost = "127.0.0.1"
		}
		a.ReverseProxyTo = net.JoinHostPort(dialHost, port)
		bindTCP = append([]string{port}, bindTCP...)
		fallback = kindCommand(k, env)
	}
	asApp := command != nil
	if !asApp {
		command = fallback
	}
	setDefault(env, "PATH", os.Getenv("PATH"))
	setDefault(env, "HOME", filepath.Join(appDir, "data"))
	setDefault(env, "TMPDIR", "data")
	if k == denoApp {
		env["DENO_NO_UPDATE_CHECK"] = "1"
	}
	names := slices.Sorted(maps.Keys(env))
	for _, name := range names {
		a.Envs = append(a.Envs, name+"="+env[name])
	}
	a.Executable = command
	if sandboxed {
		p, err := RuntimePolicy(appDir, k == staticApp, socketDir)
		if err != nil {
			return App{}, err
		}
		if writable {
			p = p.WithWritable(appDir)
		}
		// The app binds its own port, ports the kernel picks (bind to port 0;
		// dev workers and test servers do this), and REVERSE_BIN_BIND_TCP: its
		// code cannot choose another app's port, or Caddy's, to share with
		// SO_REUSEPORT. Port 0 adds nothing: Landlock does not govern autobind,
		// so listen() without bind() gets a kernel-picked port anyway. This
		// confines the running app, not its owner: .env chooses the ports, and
		// --as-app commands (dev sessions) bind as they please.
		if k != staticApp && !asApp {
			p.bindTCP = append([]string{"0"}, bindTCP...)
		}
		// sh, not the app, is PID 1 of the namespace: PID 1 ignores signals it
		// has no handler for, so most apps would never see reverse-bin's SIGTERM.
		command = append([]string{"/bin/sh", "-c", `"$@"; exit $?`, "sh"}, command...)
		// Absolute paths, resolved with the detector's PATH: the command runs
		// with the app's env, and unshare would find landrun through the app's
		// PATH, letting an app substitute its own and run unsandboxed.
		unshare, err := exec.LookPath("unshare")
		if err != nil {
			return App{}, err
		}
		landrun, err := exec.LookPath("landrun")
		if err != nil {
			return App{}, err
		}
		if !filepath.IsAbs(unshare) || !filepath.IsAbs(landrun) {
			return App{}, fmt.Errorf("sandbox tools must resolve to absolute paths: %s %s", unshare, landrun)
		}
		argv := Command(p, names, command)
		argv[0] = landrun
		a.Executable = wrapPIDNamespace(unshare, argv)
	}
	return a, nil
}

func wrapPIDNamespace(unshare string, command []string) []string {
	wrapped := []string{unshare, "--map-current-user", "--pid", "--fork", "--mount-proc", "--ipc", "--uts", "--kill-child", "--"}
	return append(wrapped, command...)
}

func kindCommand(k kind, env map[string]string) []string {
	if k == denoApp {
		return []string{"deno", "serve", "--watch", "--allow-all", "--host", env[KeyReverseBinHost], "--port", env[KeyReverseBinPort], "main.ts"}
	}
	return []string{"sh", "-c", env[KeyReverseBinCommand]}
}

func setDefault(env map[string]string, k, v string) {
	if _, ok := env[k]; !ok && v != "" {
		env[k] = v
	}
}

// detectKind returns the app's kind, and for static apps the root to serve.
func detectKind(appDir string, env map[string]string) (kind, string, error) {
	if env[KeyReverseBinCommand] != "" {
		return explicitApp, "", nil
	}
	for _, c := range []struct {
		name string
		kind kind
		root string
	}{
		{"main.ts", denoApp, ""},
		{"index.html", staticApp, "."},
		{filepath.Join("dist", "index.html"), staticApp, "dist"},
	} {
		if ok, err := isFile(appDir, c.name); ok || err != nil {
			return c.kind, c.root, err
		}
	}
	return "", "", fmt.Errorf("no entry point (%s, main.ts, index.html or dist/index.html) in %s", KeyReverseBinCommand, appDir)
}

// isFile stats through os.Root: a symlink out of appDir is an error.
func isFile(appDir, name string) (bool, error) {
	root, err := os.OpenRoot(appDir)
	if err != nil {
		return false, err
	}
	defer root.Close()
	st, err := root.Stat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return err == nil && st.Mode().IsRegular(), err
}

var portSpec = regexp.MustCompile(`^[0-9]{1,5}(-[0-9]{1,5})?$`)

// parseBindTCP reads REVERSE_BIN_BIND_TCP: extra fixed TCP ports or ranges the
// app may bind, comma-separated. landrun checks the numbers' range. 0, which
// v0.4.0 needed for kernel-picked ports, is granted to every app now and is
// dropped here.
func parseBindTCP(v string) ([]string, error) {
	if v == "" {
		return nil, nil
	}
	var ports []string
	for p := range strings.SplitSeq(v, ",") {
		if !portSpec.MatchString(p) {
			return nil, fmt.Errorf("%s=%s: want ports or ranges like 9229,32000-32768", KeyReverseBinBindTCP, v)
		}
		if p != "0" {
			ports = append(ports, p)
		}
	}
	return ports, nil
}

// appSocket resolves SOCKET_PATH, which must stay inside appDir, and creates
// its directory: off-the-shelf servers bind but do not mkdir.
func appSocket(appDir, rel string) (string, error) {
	if !filepath.IsLocal(rel) {
		return "", fmt.Errorf("%s must be a relative path inside the app directory", KeySocketPath)
	}
	// reverse-bin rejects braces in the address: Caddy would expand them.
	if strings.ContainsAny(rel, "{}") {
		return "", fmt.Errorf("%s must not contain braces", KeySocketPath)
	}
	root, err := os.OpenRoot(appDir)
	if err != nil {
		return "", err
	}
	defer root.Close()
	if err := root.MkdirAll(filepath.Dir(rel), 0o700); err != nil {
		return "", fmt.Errorf("%s directory: %w", KeySocketPath, err)
	}
	return filepath.Join(appDir, rel), nil
}

func freePort(host string) (string, error) {
	l, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		return "", fmt.Errorf("pick a free port: %w", err)
	}
	defer l.Close()
	return strconv.Itoa(l.Addr().(*net.TCPAddr).Port), nil
}

// setPublicHost sets REVERSE_BIN_PUBLIC_HOST from --public-host unless the
// app sets it. Apps serve it as https://HOST.
func setPublicHost(env map[string]string, flagHost string) error {
	host, ok := env[KeyReverseBinPublicHost]
	if !ok {
		host = flagHost
	}
	if host == "" {
		return nil
	}
	host = strings.ToLower(host)
	u, err := url.Parse("https://" + host)
	if err != nil || u.Host != host || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return fmt.Errorf("public host must be host[:port] like app.example.com: %q", host)
	}
	env[KeyReverseBinPublicHost] = host
	return nil
}

// loadEnv reads APP/.env or decrypts APP/secrets.enc.json through os.Root, so
// a tenant's symlink to another app's files is an error.
func loadEnv(ctx context.Context, appDir string, sandboxed bool) (map[string]string, error) {
	root, err := os.OpenRoot(appDir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	read := func(name string) ([]byte, error) {
		data, err := root.ReadFile(name)
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return data, err
	}
	dotEnv, err := read(".env")
	if err != nil {
		return nil, err
	}
	secrets, err := read("secrets.enc.json")
	switch {
	case err != nil:
		return nil, err
	case dotEnv != nil && secrets != nil:
		return nil, errors.New("use .env or secrets.enc.json, not both")
	case secrets != nil:
		plain, err := decryptSOPS(ctx, secrets, sandboxed)
		if err != nil {
			return nil, fmt.Errorf("decrypt secrets.enc.json: %w", err)
		}
		return parseDotEnv(plain)
	}
	return parseDotEnv(dotEnv)
}

// decryptSOPS feeds ciphertext to sops on stdin, so sops opens no app path.
func decryptSOPS(ctx context.Context, ciphertext []byte, sandboxed bool) ([]byte, error) {
	sops, err := exec.LookPath("sops")
	if err != nil {
		return nil, err
	}
	argv := []string{sops, "decrypt", "--input-type", "json", "--output-type", "dotenv"}
	if sandboxed {
		key := os.Getenv("SOPS_AGE_KEY_FILE")
		var names []string
		if key != "" {
			names = []string{"SOPS_AGE_KEY_FILE"}
		}
		argv = Command(SOPSPolicy(sops, key), names, argv)
	}
	// Tenant metadata naming KMS makes sops retry for ~13s with every connect
	// denied; Caddy is waiting for the plan.
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Stdin = bytes.NewReader(ciphertext)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if ctx.Err() != nil {
		return nil, fmt.Errorf("sops timed out after 5s; does secrets.enc.json name non-age keys? %w", ctx.Err())
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

func parseDotEnv(content []byte) (map[string]string, error) {
	env := map[string]string{}
	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(scanner.Text()), "export "))
		name, value, ok := strings.Cut(line, "=")
		name = strings.TrimSpace(name)
		if !ok || name == "" || strings.HasPrefix(line, "#") {
			continue
		}
		value = strings.TrimSpace(value)
		if len(value) >= 2 && (value[0] == '\'' || value[0] == '"') && value[len(value)-1] == value[0] {
			value = value[1 : len(value)-1]
		}
		env[name] = value
	}
	if err := scanner.Err(); err != nil { // a line over 64 KiB: never drop the rest silently
		return nil, fmt.Errorf("env file: %w", err)
	}
	return env, nil
}
