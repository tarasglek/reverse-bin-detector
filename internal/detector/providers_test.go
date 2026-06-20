package detector

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestResolveAppDetectsMainTS(t *testing.T) {
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
}

func TestResolveAppDetectsExecutableMainPY(t *testing.T) {
	appDir := t.TempDir()
	writeFile(t, filepath.Join(appDir, "main.py"), "#!/usr/bin/env python3\n")
	if err := os.Chmod(filepath.Join(appDir, "main.py"), 0o755); err != nil {
		t.Fatal(err)
	}

	resolved, err := ResolveApp(context.Background(), appDir, map[string]string{"SOCKET_PATH": "data/app.sock"})
	if err != nil {
		t.Fatalf("ResolveApp: %v", err)
	}
	if !reflect.DeepEqual(resolved.Executable, []string{"./main.py"}) {
		t.Fatalf("Executable = %#v", resolved.Executable)
	}
	if !strings.HasPrefix(resolved.ReverseProxyTo, "unix/") || !strings.HasSuffix(resolved.ReverseProxyTo, "/data/app.sock") {
		t.Fatalf("ReverseProxyTo = %q, want unix app socket", resolved.ReverseProxyTo)
	}
}

func TestResolveAppIgnoresNonExecutableMainPY(t *testing.T) {
	appDir := t.TempDir()
	writeFile(t, filepath.Join(appDir, "main.py"), "print('hello')\n")

	_, err := ResolveApp(context.Background(), appDir, map[string]string{})
	if err == nil {
		t.Fatal("ResolveApp error = nil, want no entrypoint error")
	}
}

func TestResolveAppDetectsRootIndexHTML(t *testing.T) {
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

func TestResolveAppDetectsDistIndexHTML(t *testing.T) {
	appDir := t.TempDir()
	dist := filepath.Join(appDir, "dist")
	if err := os.Mkdir(dist, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dist, "index.html"), "<h1>static</h1>\n")

	resolved, err := ResolveApp(context.Background(), appDir, map[string]string{"REVERSE_BIN_PORT": "8080"})
	if err != nil {
		t.Fatalf("ResolveApp: %v", err)
	}
	want := []string{"reverse-bin-caddy", "file-server", "--listen", "127.0.0.1:8080", "--root", "dist"}
	if !reflect.DeepEqual(resolved.Executable, want) {
		t.Fatalf("Executable = %#v, want %#v", resolved.Executable, want)
	}
}

func TestResolveAppPrefersDetectionOrder(t *testing.T) {
	appDir := t.TempDir()
	writeFile(t, filepath.Join(appDir, "main.ts"), "console.log('hello')\n")
	writeFile(t, filepath.Join(appDir, "main.py"), "#!/usr/bin/env python3\n")
	if err := os.Chmod(filepath.Join(appDir, "main.py"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(appDir, "index.html"), "<h1>static</h1>\n")

	resolved, err := ResolveApp(context.Background(), appDir, map[string]string{"REVERSE_BIN_PORT": "8080"})
	if err != nil {
		t.Fatalf("ResolveApp: %v", err)
	}
	if got := resolved.Executable[len(resolved.Executable)-1]; got != "main.ts" {
		t.Fatalf("selected %q, want main.ts first", got)
	}
}

func TestResolveAppExplicitCommandWins(t *testing.T) {
	appDir := t.TempDir()
	writeFile(t, filepath.Join(appDir, "main.ts"), "console.log('hello')\n")

	resolved, err := ResolveApp(context.Background(), appDir, map[string]string{"REVERSE_BIN_COMMAND": "python3 server.py", "REVERSE_BIN_PORT": "8080"})
	if err != nil {
		t.Fatalf("ResolveApp: %v", err)
	}
	want := []string{"sh", "-c", "python3 server.py"}
	if !reflect.DeepEqual(resolved.Executable, want) {
		t.Fatalf("Executable = %#v, want %#v", resolved.Executable, want)
	}
}
