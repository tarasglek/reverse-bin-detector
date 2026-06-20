package detector

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestResolveAppUsesExplicitReverseBinPort(t *testing.T) {
	appDir := makeExecutableMainPyApp(t)
	resolved, err := ResolveApp(context.Background(), appDir, map[string]string{"REVERSE_BIN_PORT": "7777"})
	if err != nil {
		t.Fatalf("ResolveApp: %v", err)
	}
	if resolved.ReverseProxyTo != "127.0.0.1:7777" {
		t.Fatalf("ReverseProxyTo = %q", resolved.ReverseProxyTo)
	}
}

func TestResolveAppUsesExplicitListenPort(t *testing.T) {
	appDir := makeExecutableMainPyApp(t)
	resolved, err := ResolveApp(context.Background(), appDir, map[string]string{"LISTEN": "7777"})
	if err != nil {
		t.Fatalf("ResolveApp: %v", err)
	}
	if resolved.ReverseProxyTo != "127.0.0.1:7777" {
		t.Fatalf("ReverseProxyTo = %q", resolved.ReverseProxyTo)
	}
}

func TestResolveAppAllocatesFreePortForBlankReverseBinPort(t *testing.T) {
	appDir := makeExecutableMainPyApp(t)
	resolved, err := ResolveApp(context.Background(), appDir, map[string]string{"REVERSE_BIN_PORT": ""})
	if err != nil {
		t.Fatalf("ResolveApp: %v", err)
	}
	assertLocalPort(t, resolved.ReverseProxyTo)
	if resolved.ReverseProxyTo == "127.0.0.1:8080" {
		t.Fatalf("ReverseProxyTo = %q, want detector-selected free port", resolved.ReverseProxyTo)
	}
}

func TestResolveAppAllocatesFreePortForBlankListen(t *testing.T) {
	appDir := makeExecutableMainPyApp(t)
	resolved, err := ResolveApp(context.Background(), appDir, map[string]string{"LISTEN": ""})
	if err != nil {
		t.Fatalf("ResolveApp: %v", err)
	}
	assertLocalPort(t, resolved.ReverseProxyTo)
	if got := resolved.EnvOverrides[KeyListen]; got != resolved.ReverseProxyTo {
		t.Fatalf("LISTEN override = %q, want %q", got, resolved.ReverseProxyTo)
	}
}

func TestResolveAppUsesSocketPath(t *testing.T) {
	appDir := makeExecutableMainPyApp(t)
	resolved, err := ResolveApp(context.Background(), appDir, map[string]string{"SOCKET_PATH": "data/app.sock"})
	if err != nil {
		t.Fatalf("ResolveApp: %v", err)
	}
	wantSuffix := filepath.Join("data", "app.sock")
	if !strings.HasPrefix(resolved.ReverseProxyTo, "unix/") || !strings.HasSuffix(resolved.ReverseProxyTo, wantSuffix) {
		t.Fatalf("ReverseProxyTo = %q", resolved.ReverseProxyTo)
	}
}

func TestResolveAppRejectsAbsoluteSocketPath(t *testing.T) {
	appDir := makeExecutableMainPyApp(t)
	_, err := ResolveApp(context.Background(), appDir, map[string]string{"SOCKET_PATH": "/tmp/app.sock"})
	if err == nil {
		t.Fatal("ResolveApp error = nil, want absolute socket path error")
	}
}

func TestResolveAppDefaultsPythonToSocketPath(t *testing.T) {
	appDir := makeExecutableMainPyApp(t)
	resolved, err := ResolveApp(context.Background(), appDir, map[string]string{})
	if err != nil {
		t.Fatalf("ResolveApp: %v", err)
	}
	want := "unix/" + filepath.Join(appDir, "data", "reverse-bin.sock")
	if resolved.ReverseProxyTo != want {
		t.Fatalf("ReverseProxyTo = %q, want %q", resolved.ReverseProxyTo, want)
	}
}

func TestResolveAppDefaultsDenoToDetectorSelectedTCP(t *testing.T) {
	appDir := t.TempDir()
	writeFile(t, filepath.Join(appDir, "main.ts"), "console.log('hello')\n")
	resolved, err := ResolveApp(context.Background(), appDir, map[string]string{})
	if err != nil {
		t.Fatalf("ResolveApp: %v", err)
	}
	assertLocalPort(t, resolved.ReverseProxyTo)
}

func TestResolveAppDefaultsStaticToDetectorSelectedTCP(t *testing.T) {
	appDir := t.TempDir()
	writeFile(t, filepath.Join(appDir, "index.html"), "<h1>static</h1>\n")
	resolved, err := ResolveApp(context.Background(), appDir, map[string]string{})
	if err != nil {
		t.Fatalf("ResolveApp: %v", err)
	}
	assertLocalPort(t, resolved.ReverseProxyTo)
}

func makeExecutableMainPyApp(t *testing.T) string {
	t.Helper()
	appDir := t.TempDir()
	path := filepath.Join(appDir, "main.py")
	writeFile(t, path, "#!/usr/bin/env python3\n")
	if err := os.Chmod(path, 0o755); err != nil {
		t.Fatal(err)
	}
	return appDir
}

func assertLocalPort(t *testing.T, addr string) {
	t.Helper()
	if !regexp.MustCompile(`^127\.0\.0\.1:\d+$`).MatchString(addr) {
		t.Fatalf("addr = %q, want local TCP port", addr)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("expected %s to be free after detector allocation: %v", addr, err)
	}
	_ = ln.Close()
}
