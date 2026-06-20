package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tarasglek/caddy-reverse-bin/detectorschema"
)

func TestCLIPythonSocketAppOutput(t *testing.T) {
	appDir := t.TempDir()
	mainPy := filepath.Join(appDir, "main.py")
	if err := os.WriteFile(mainPy, []byte("#!/usr/bin/env python3\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	payload := runDetectorOK(t, appDir)
	if got := *payload.Executable; len(got) == 0 || got[len(got)-1] != "./main.py" {
		t.Fatalf("Executable = %#v", got)
	}
	if !strings.HasPrefix(*payload.ReverseProxyTo, "unix/") || !strings.HasSuffix(*payload.ReverseProxyTo, "/data/reverse-bin.sock") {
		t.Fatalf("ReverseProxyTo = %q", *payload.ReverseProxyTo)
	}
}

func TestCLIStaticTCPAppOutput(t *testing.T) {
	appDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(appDir, "index.html"), []byte("<h1>static</h1>\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(appDir, ".env"), []byte("REVERSE_BIN_PORT=9999\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	payload := runDetectorOK(t, appDir)
	if got := strings.Join(*payload.Executable, " "); !strings.Contains(got, "reverse-bin-caddy file-server") {
		t.Fatalf("Executable = %#v", *payload.Executable)
	}
	if *payload.ReverseProxyTo != "127.0.0.1:9999" {
		t.Fatalf("ReverseProxyTo = %q", *payload.ReverseProxyTo)
	}
}

func TestCLIInvalidAppExitsNonZero(t *testing.T) {
	appDir := t.TempDir()
	cmd := exec.Command("go", "run", ".", "--allow-unsafe-no-landlock", "--no-runtime-sandbox", appDir)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("detector succeeded, want failure; output %s", out)
	}
	if !strings.Contains(string(out), "No supported entry point") {
		t.Fatalf("output = %q, want no entrypoint error", out)
	}
}

func runDetectorOK(t *testing.T, appDir string) *detectorschema.DetectorOutput {
	t.Helper()
	cmd := exec.Command("go", "run", ".", "--allow-unsafe-no-landlock", "--no-runtime-sandbox", appDir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("detector failed: %v\n%s", err, out)
	}
	payload, err := detectorschema.Parse(out)
	if err != nil {
		t.Fatalf("schema parse failed: %v\n%s", err, out)
	}
	var unknown map[string]json.RawMessage
	if err := json.Unmarshal(out, &unknown); err != nil {
		t.Fatal(err)
	}
	return payload
}
