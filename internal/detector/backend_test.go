package detector

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestResolveAppBuildsPythonCommand(t *testing.T) {
	appDir := makeExecutableMainPyApp(t)
	resolved, err := ResolveApp(context.Background(), appDir, map[string]string{})
	if err != nil {
		t.Fatalf("ResolveApp: %v", err)
	}
	if !reflect.DeepEqual(resolved.Executable, []string{"./main.py"}) {
		t.Fatalf("Executable = %#v", resolved.Executable)
	}
}

func TestResolveAppBuildsDenoCommandAndEnv(t *testing.T) {
	appDir := t.TempDir()
	writeFile(t, filepath.Join(appDir, "main.ts"), "console.log('hello')\n")
	resolved, err := ResolveApp(context.Background(), appDir, map[string]string{"REVERSE_BIN_PORT": "8080"})
	if err != nil {
		t.Fatalf("ResolveApp: %v", err)
	}
	want := []string{"deno", "serve", "--watch", "--allow-all", "--host", "127.0.0.1", "--port", "8080", "main.ts"}
	if !reflect.DeepEqual(resolved.Executable, want) {
		t.Fatalf("Executable = %#v, want %#v", resolved.Executable, want)
	}
	if got := envMap(resolved.Envs)["DENO_NO_UPDATE_CHECK"]; got != "1" {
		t.Fatalf("DENO_NO_UPDATE_CHECK = %q, want 1", got)
	}
}

func TestResolveAppBuildsFileServerCommand(t *testing.T) {
	appDir := t.TempDir()
	writeFile(t, filepath.Join(appDir, "index.html"), "<h1>static</h1>\n")
	resolved, err := ResolveApp(context.Background(), appDir, map[string]string{"REVERSE_BIN_PORT": "8080"})
	if err != nil {
		t.Fatalf("ResolveApp: %v", err)
	}
	want := []string{"reverse-bin-caddy", "file-server", "--listen", "127.0.0.1:8080", "--root", "."}
	if !reflect.DeepEqual(resolved.Executable, want) {
		t.Fatalf("Executable = %#v, want %#v", resolved.Executable, want)
	}
}

func TestResolveAppBuildsEnvOutputAsKeyValue(t *testing.T) {
	appDir := makeExecutableMainPyApp(t)
	resolved, err := ResolveApp(context.Background(), appDir, map[string]string{"CUSTOM": "1", "SOCKET_PATH": "data/app.sock"})
	if err != nil {
		t.Fatalf("ResolveApp: %v", err)
	}
	envs := envMap(resolved.Envs)
	if envs["CUSTOM"] != "1" {
		t.Fatalf("CUSTOM = %q, want 1 in %#v", envs["CUSTOM"], resolved.Envs)
	}
	if envs["SOCKET_PATH"] != "data/app.sock" {
		t.Fatalf("SOCKET_PATH = %q", envs["SOCKET_PATH"])
	}
}

func TestResolveAppCopiesPathIfMissing(t *testing.T) {
	t.Setenv("PATH", "/test/bin")
	appDir := makeExecutableMainPyApp(t)
	resolved, err := ResolveApp(context.Background(), appDir, map[string]string{})
	if err != nil {
		t.Fatalf("ResolveApp: %v", err)
	}
	if got := envMap(resolved.Envs)["PATH"]; got != "/test/bin" {
		t.Fatalf("PATH = %q, want /test/bin", got)
	}
}

func TestResolveAppKeepsPathFromAppEnv(t *testing.T) {
	t.Setenv("PATH", "/host/bin")
	appDir := makeExecutableMainPyApp(t)
	resolved, err := ResolveApp(context.Background(), appDir, map[string]string{"PATH": "/app/bin"})
	if err != nil {
		t.Fatalf("ResolveApp: %v", err)
	}
	if got := envMap(resolved.Envs)["PATH"]; got != "/app/bin" {
		t.Fatalf("PATH = %q, want /app/bin", got)
	}
}

func TestResolveAppSetsHomeToDataWhenDataExists(t *testing.T) {
	appDir := makeExecutableMainPyApp(t)
	dataDir := filepath.Join(appDir, "data")
	if err := os.Mkdir(dataDir, 0o755); err != nil {
		t.Fatal(err)
	}
	resolved, err := ResolveApp(context.Background(), appDir, map[string]string{})
	if err != nil {
		t.Fatalf("ResolveApp: %v", err)
	}
	if got := envMap(resolved.Envs)["HOME"]; got != dataDir {
		t.Fatalf("HOME = %q, want %q", got, dataDir)
	}
}

func envMap(envs []string) map[string]string {
	out := map[string]string{}
	for _, entry := range envs {
		name, value, ok := stringsCut(entry, "=")
		if ok {
			out[name] = value
		}
	}
	return out
}

func stringsCut(s, sep string) (string, string, bool) {
	for i := 0; i+len(sep) <= len(s); i++ {
		if s[i:i+len(sep)] == sep {
			return s[:i], s[i+len(sep):], true
		}
	}
	return s, "", false
}
