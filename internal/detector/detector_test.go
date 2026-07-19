package detector

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/tarasglek/caddy-reverse-bin/detectorschema"
)

type testFile struct {
	body string
	mode os.FileMode
}

func TestResolveAppBehavior(t *testing.T) {
	t.Setenv("PATH", "/test/bin")
	tests := []struct {
		name           string
		files          map[string]testFile
		env            map[string]string
		wantCmd        []string
		wantProxy      string
		wantEnv        map[string]string
		wantRoot       string
		wantErr        string
		localProxy     bool
		wantStaticRoot string
	}{
		{
			name:      "explicit command wins",
			files:     map[string]testFile{"main.ts": {body: "console.log('ignored')\n"}},
			env:       map[string]string{"REVERSE_BIN_COMMAND": "python3 server.py", "REVERSE_BIN_PORT": "8080"},
			wantCmd:   []string{"sh", "-c", "python3 server.py"},
			wantProxy: "127.0.0.1:8080",
		},
		{
			name:      "deno main ts",
			files:     map[string]testFile{"main.ts": {body: "console.log('hello')\n"}},
			env:       map[string]string{"REVERSE_BIN_PORT": "8080"},
			wantCmd:   []string{"deno", "serve", "--watch", "--allow-all", "--host", "127.0.0.1", "--port", "8080", "main.ts"},
			wantProxy: "127.0.0.1:8080",
			wantEnv:   map[string]string{"DENO_NO_UPDATE_CHECK": "1", "TMPDIR": "data"},
		},
		{
			name:      "python executable defaults to unix socket",
			files:     map[string]testFile{"main.py": {body: "#!/usr/bin/env python3\n", mode: 0o755}},
			wantCmd:   []string{"./main.py"},
			wantProxy: "unix/",
			wantEnv:   map[string]string{"SOCKET_PATH": filepath.Join("data", "reverse-bin.sock")},
		},
		{
			name:           "static root defaults to managed unix socket",
			files:          map[string]testFile{"index.html": {body: "<h1>static</h1>\n"}},
			wantStaticRoot: ".",
		},
		{
			name:           "static dist defaults to managed unix socket",
			files:          map[string]testFile{"dist/index.html": {body: "<h1>static</h1>\n"}},
			wantStaticRoot: "dist",
		},
		{
			name:    "static socket config rejected",
			files:   map[string]testFile{"index.html": {body: "<h1>static</h1>\n"}},
			env:     map[string]string{"SOCKET_PATH": "data/static.sock"},
			wantErr: "static file server only supports reverse-bin-managed Unix sockets",
		},
		{
			name:    "static port config rejected",
			files:   map[string]testFile{"index.html": {body: "<h1>static</h1>\n"}},
			env:     map[string]string{"REVERSE_BIN_PORT": "8080"},
			wantErr: "static file server only supports reverse-bin-managed Unix sockets",
		},
		{
			name:    "static listen config rejected",
			files:   map[string]testFile{"index.html": {body: "<h1>static</h1>\n"}},
			env:     map[string]string{"LISTEN": "127.0.0.1:8080"},
			wantErr: "static file server only supports reverse-bin-managed Unix sockets",
		},
		{
			name:    "static host config rejected",
			files:   map[string]testFile{"index.html": {body: "<h1>static</h1>\n"}},
			env:     map[string]string{"REVERSE_BIN_HOST": "127.0.0.1"},
			wantErr: "static file server only supports reverse-bin-managed Unix sockets",
		},
		{
			name:    "static blank port config rejected",
			files:   map[string]testFile{"index.html": {body: "<h1>static</h1>\n"}},
			env:     map[string]string{"REVERSE_BIN_PORT": ""},
			wantErr: "static file server only supports reverse-bin-managed Unix sockets",
		},
		{
			name:    "static blank listen config rejected",
			files:   map[string]testFile{"index.html": {body: "<h1>static</h1>\n"}},
			env:     map[string]string{"LISTEN": ""},
			wantErr: "static file server only supports reverse-bin-managed Unix sockets",
		},
		{
			name:    "static blank host config rejected",
			files:   map[string]testFile{"index.html": {body: "<h1>static</h1>\n"}},
			env:     map[string]string{"REVERSE_BIN_HOST": ""},
			wantErr: "static file server only supports reverse-bin-managed Unix sockets",
		},
		{
			name:    "non executable python is ignored",
			files:   map[string]testFile{"main.py": {body: "print('hello')\n", mode: 0o644}},
			wantErr: "No supported entry point",
		},
		{
			name:      "explicit socket path",
			files:     map[string]testFile{"main.py": {body: "#!/usr/bin/env python3\n", mode: 0o755}},
			env:       map[string]string{"SOCKET_PATH": "data/app.sock", "CUSTOM": "1"},
			wantCmd:   []string{"./main.py"},
			wantProxy: "unix/",
			wantEnv:   map[string]string{"CUSTOM": "1", "SOCKET_PATH": "data/app.sock"},
		},
		{
			name:       "blank port allocates local tcp and injects override",
			files:      map[string]testFile{"main.ts": {body: "console.log('hello')\n"}},
			env:        map[string]string{"REVERSE_BIN_PORT": ""},
			localProxy: true,
			wantEnv:    map[string]string{"REVERSE_BIN_HOST": "127.0.0.1"},
		},
		{
			name:    "absolute socket path rejected",
			files:   map[string]testFile{"main.py": {body: "#!/usr/bin/env python3\n", mode: 0o755}},
			env:     map[string]string{"SOCKET_PATH": "/tmp/app.sock"},
			wantErr: "Unix socket path must be relative",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			appDir := makeApp(t, tt.files)
			resolved, err := ResolveApp(context.Background(), appDir, tt.env)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("ResolveApp error = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveApp: %v", err)
			}
			if tt.wantCmd != nil && !reflect.DeepEqual(*resolved.Executable, tt.wantCmd) {
				t.Fatalf("Executable = %#v, want %#v", *resolved.Executable, tt.wantCmd)
			}
			if tt.wantProxy != "" && !strings.HasPrefix(*resolved.ReverseProxyTo, tt.wantProxy) {
				t.Fatalf("ReverseProxyTo = %q, want prefix %q", *resolved.ReverseProxyTo, tt.wantProxy)
			}
			if tt.localProxy {
				assertLocalTCP(t, *resolved.ReverseProxyTo)
			}
			if tt.wantStaticRoot != "" {
				assertStaticUnix(t, resolved, tt.wantStaticRoot)
			}
			envs := envMap(*resolved.Envs)
			if got := envs["PATH"]; got != "/test/bin" {
				t.Fatalf("PATH = %q, want /test/bin", got)
			}
			for key, want := range tt.wantEnv {
				if got := envs[key]; got != want {
					t.Fatalf("env %s = %q, want %q", key, got, want)
				}
			}
		})
	}
}

func TestCommandForRejectsStaticTCPTransport(t *testing.T) {
	_, err := commandFor(app{kind: staticApp, root: "."}, transport{kind: "tcp", listen: "127.0.0.1:8080"})
	if err == nil || !strings.Contains(err.Error(), "only supports Unix sockets") {
		t.Fatalf("commandFor error = %v, want static Unix-only error", err)
	}
}

func TestResolveStaticAppRuntimeSandboxUsesOnlySocketDirectory(t *testing.T) {
	appDir := makeApp(t, map[string]testFile{
		"index.html": {body: "<h1>static</h1>\n"},
		"data/.keep": {body: ""},
	})
	resolved, err := ResolveAppWithRuntimeSandbox(context.Background(), appDir, nil, true)
	if err != nil {
		t.Fatalf("ResolveAppWithRuntimeSandbox: %v", err)
	}
	cmd := strings.Join(*resolved.Executable, " ")
	if strings.Contains(cmd, "--unrestricted-network") {
		t.Fatalf("static sandbox command contains --unrestricted-network: %q", cmd)
	}
	if strings.Contains(cmd, "--bind-tcp") {
		t.Fatalf("static sandbox command contains --bind-tcp: %q", cmd)
	}
	if !strings.Contains(cmd, "--rw /run/reverse-bin/static-apps/app-") {
		t.Fatalf("static sandbox command missing runtime socket dir: %q", cmd)
	}
	if strings.Contains(cmd, "--rw "+filepath.Join(appDir, "data")) {
		t.Fatalf("static sandbox command grants app data write access: %q", cmd)
	}
}

func TestExecutableAppRuntimeSandboxesUseUnrestrictedNetwork(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]testFile
		env   map[string]string
	}{
		{
			name: "command",
			env:  map[string]string{"REVERSE_BIN_COMMAND": "server", "REVERSE_BIN_PORT": "7777"},
		},
		{
			name:  "deno",
			files: map[string]testFile{"main.ts": {body: "console.log('hello')\n"}},
			env:   map[string]string{"REVERSE_BIN_PORT": "7777"},
		},
		{
			name:  "python",
			files: map[string]testFile{"main.py": {body: "#!/usr/bin/env python3\n", mode: 0o755}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			appDir := makeApp(t, tt.files)
			resolved, err := ResolveAppWithRuntimeSandbox(context.Background(), appDir, tt.env, true)
			if err != nil {
				t.Fatalf("ResolveAppWithRuntimeSandbox: %v", err)
			}
			cmd := strings.Join(*resolved.Executable, " ")
			if !strings.Contains(cmd, "--unrestricted-network") {
				t.Fatalf("executable sandbox command missing --unrestricted-network: %q", cmd)
			}
			if strings.Contains(cmd, "--bind-tcp") {
				t.Fatalf("executable sandbox command contains --bind-tcp: %q", cmd)
			}
		})
	}
}

func TestResolveAppRuntimeSandbox(t *testing.T) {
	appDir := makeApp(t, map[string]testFile{"main.ts": {body: "console.log('hello')\n"}})
	resolved, err := ResolveAppWithRuntimeSandbox(context.Background(), appDir, map[string]string{"REVERSE_BIN_PORT": "7777"}, true)
	if err != nil {
		t.Fatalf("ResolveAppWithRuntimeSandbox: %v", err)
	}
	wantPrefix := []string{"unshare", "--map-current-user", "--pid", "--fork", "--mount-proc", "--ipc", "--uts", "--kill-child", "--", "landrun"}
	if len(*resolved.Executable) < len(wantPrefix) || !reflect.DeepEqual((*resolved.Executable)[:len(wantPrefix)], wantPrefix) {
		t.Fatalf("wrapped command prefix = %#v, want %#v", (*resolved.Executable)[:min(len(*resolved.Executable), len(wantPrefix))], wantPrefix)
	}
	cmd := strings.Join(*resolved.Executable, " ")
	for _, want := range []string{"--env DENO_NO_UPDATE_CHECK=1", "--rox " + appDir, "--unrestricted-network", "deno serve"} {
		if !strings.Contains(cmd, want) {
			t.Fatalf("wrapped command %q missing %q", cmd, want)
		}
	}

	plain, err := ResolveAppWithRuntimeSandbox(context.Background(), appDir, map[string]string{"REVERSE_BIN_PORT": "7777"}, false)
	if err != nil {
		t.Fatalf("ResolveAppWithRuntimeSandbox no sandbox: %v", err)
	}
	if len(*plain.Executable) == 0 || (*plain.Executable)[0] == "landrun" {
		t.Fatalf("NoRuntimeSandbox executable = %#v, want unwrapped", *plain.Executable)
	}
}

func makeApp(t *testing.T, files map[string]testFile) string {
	t.Helper()
	appDir := t.TempDir()
	for name, f := range files {
		mode := f.mode
		if mode == 0 {
			mode = 0o644
		}
		path := filepath.Join(appDir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(path, []byte(f.body), mode); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
	return appDir
}

func envMap(envs []string) map[string]string {
	out := map[string]string{}
	for _, env := range envs {
		key, value, ok := strings.Cut(env, "=")
		if ok {
			out[key] = value
		}
	}
	return out
}

func assertStaticUnix(t *testing.T, resolved detectorschema.DetectorOutput, root string) {
	t.Helper()
	proxy := *resolved.ReverseProxyTo
	if !strings.HasPrefix(proxy, "unix//run/reverse-bin/static-apps/app-") || !strings.HasSuffix(proxy, "/reverse-bin.sock") {
		t.Fatalf("ReverseProxyTo = %q, want managed static Unix socket", proxy)
	}
	listen := "unix//" + strings.TrimPrefix(proxy, "unix/")
	want := []string{"reverse-bin-caddy", "file-server", "--listen", listen, "--root", root}
	if !reflect.DeepEqual(*resolved.Executable, want) {
		t.Fatalf("Executable = %#v, want %#v", *resolved.Executable, want)
	}
}

func assertLocalTCP(t *testing.T, addr string) {
	t.Helper()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", addr, err)
	}
	if host != "127.0.0.1" || port == "" {
		t.Fatalf("addr = %q, want 127.0.0.1:<port>", addr)
	}
}
