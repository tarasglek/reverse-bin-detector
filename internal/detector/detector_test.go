package detector

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type testFile struct {
	body string
	mode os.FileMode
}

func TestResolveAppBehavior(t *testing.T) {
	t.Setenv("PATH", "/test/bin")
	tests := []struct {
		name       string
		files      map[string]testFile
		env        map[string]string
		wantCmd    []string
		wantProxy  string
		wantEnv    map[string]string
		wantRoot   string
		wantErr    string
		localProxy bool
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
			wantEnv:   map[string]string{"DENO_NO_UPDATE_CHECK": "1"},
		},
		{
			name:      "python executable defaults to unix socket",
			files:     map[string]testFile{"main.py": {body: "#!/usr/bin/env python3\n", mode: 0o755}},
			wantCmd:   []string{"./main.py"},
			wantProxy: "unix/",
			wantEnv:   map[string]string{"SOCKET_PATH": filepath.Join("data", "reverse-bin.sock")},
		},
		{
			name:      "static root",
			files:     map[string]testFile{"index.html": {body: "<h1>static</h1>\n"}},
			env:       map[string]string{"REVERSE_BIN_PORT": "8080"},
			wantCmd:   []string{"reverse-bin-caddy", "file-server", "--listen", "127.0.0.1:8080", "--root", "."},
			wantProxy: "127.0.0.1:8080",
		},
		{
			name:      "static dist",
			files:     map[string]testFile{"dist/index.html": {body: "<h1>static</h1>\n"}},
			env:       map[string]string{"REVERSE_BIN_PORT": "8080"},
			wantCmd:   []string{"reverse-bin-caddy", "file-server", "--listen", "127.0.0.1:8080", "--root", "dist"},
			wantProxy: "127.0.0.1:8080",
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
			if tt.wantCmd != nil && !reflect.DeepEqual(resolved.Executable, tt.wantCmd) {
				t.Fatalf("Executable = %#v, want %#v", resolved.Executable, tt.wantCmd)
			}
			if tt.wantProxy != "" && !strings.HasPrefix(resolved.ReverseProxyTo, tt.wantProxy) {
				t.Fatalf("ReverseProxyTo = %q, want prefix %q", resolved.ReverseProxyTo, tt.wantProxy)
			}
			if tt.localProxy {
				assertLocalTCP(t, resolved.ReverseProxyTo)
			}
			envs := envMap(resolved.Envs)
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

func TestResolveAppRuntimeSandbox(t *testing.T) {
	appDir := makeApp(t, map[string]testFile{"main.ts": {body: "console.log('hello')\n"}})
	resolved, err := ResolveAppWithOptions(context.Background(), appDir, map[string]string{"REVERSE_BIN_PORT": "7777"}, Options{})
	if err != nil {
		t.Fatalf("ResolveAppWithOptions: %v", err)
	}
	cmd := strings.Join(resolved.Executable, " ")
	for _, want := range []string{"landrun", "--env DENO_NO_UPDATE_CHECK=1", "--rox " + appDir, "--unrestricted-network", "deno serve"} {
		if !strings.Contains(cmd, want) {
			t.Fatalf("wrapped command %q missing %q", cmd, want)
		}
	}

	plain, err := ResolveAppWithOptions(context.Background(), appDir, map[string]string{"REVERSE_BIN_PORT": "7777"}, Options{NoRuntimeSandbox: true})
	if err != nil {
		t.Fatalf("ResolveAppWithOptions no sandbox: %v", err)
	}
	if len(plain.Executable) == 0 || plain.Executable[0] == "landrun" {
		t.Fatalf("NoRuntimeSandbox executable = %#v, want unwrapped", plain.Executable)
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
