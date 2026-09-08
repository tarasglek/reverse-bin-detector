package main

import (
	"bytes"
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

func TestCLIStaticUnixAppOutput(t *testing.T) {
	appDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(appDir, "index.html"), []byte("<h1>static</h1>\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	payload := runDetectorOK(t, appDir)
	got := strings.Join(*payload.Executable, " ")
	if !strings.Contains(got, "reverse-bin-caddy file-server") || !strings.Contains(got, "--listen unix///run/reverse-bin/static-apps/app-") {
		t.Fatalf("Executable = %#v", *payload.Executable)
	}
	if !strings.HasPrefix(*payload.ReverseProxyTo, "unix//run/reverse-bin/static-apps/app-") || !strings.HasSuffix(*payload.ReverseProxyTo, "/reverse-bin.sock") {
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

func requireSandboxExecBinary(t *testing.T, binDir string) string {
	t.Helper()
	binPath := filepath.Join(binDir, "reverse-bin-detector-test")
	cmd := exec.Command("go", "build", "-o", binPath, ".")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build test binary: %v\n%s", err, out)
	}
	return binPath
}

func sbAppDir(t *testing.T) string {
	t.Helper()
	appDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(appDir, "main.py"), []byte("#!/usr/bin/env python3\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return appDir
}

func TestSandboxExecWithEcho(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox exec test in short mode")
	}
	bin := requireSandboxExecBinary(t, t.TempDir())
	appDir := sbAppDir(t)

	cmd := exec.Command(bin, "--allow-unsafe-no-landlock", "--as-app", appDir, "--", "echo", "hello world")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("as-app failed: %v\nstderr: %s\nstdout: %s", err, stderr.String(), stdout.String())
	}
	if got := strings.TrimSpace(stdout.String()); got != "hello world" {
		t.Fatalf("stdout = %q, want %q", got, "hello world")
	}
}

func TestSandboxExecExactEnv(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox exec test in short mode")
	}
	bin := requireSandboxExecBinary(t, t.TempDir())
	appDir := sbAppDir(t)
	if err := os.WriteFile(filepath.Join(appDir, ".env"), []byte("CUSTOM=secret\nREVERSE_BIN_PORT=7777\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(bin, "--allow-unsafe-no-landlock", "--as-app", appDir, "--", "sh", "-c", "echo $CUSTOM; echo $USER; echo $HOME")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("as-app failed: %v\nstderr: %s\nstdout: %s", err, stderr.String(), stdout.String())
	}
	lines := strings.Split(stdout.String(), "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	if len(lines) < 3 {
		t.Fatalf("output has %d lines: %s", len(lines), stdout.String())
	}
	if lines[0] != "secret" {
		t.Fatalf("CUSTOM = %q, want secret", lines[0])
	}
	if lines[1] != "" {
		t.Fatalf("USER leaked: USER=%q", lines[1])
	}
	if lines[2] != filepath.Join(appDir, "data") {
		t.Fatalf("HOME = %q, want %q (caller HOME=%q)", lines[2], filepath.Join(appDir, "data"), os.Getenv("HOME"))
	}
}

func TestSandboxExecExitCodePropagation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox exec test in short mode")
	}
	bin := requireSandboxExecBinary(t, t.TempDir())
	appDir := sbAppDir(t)

	cmd := exec.Command(bin, "--allow-unsafe-no-landlock", "--as-app", appDir, "--", "sh", "-c", "exit 42")
	if err := cmd.Run(); err == nil {
		t.Fatal("expected exit error, got nil")
	} else if exitErr, ok := err.(*exec.ExitError); ok {
		if exitErr.ExitCode() != 42 {
			t.Fatalf("exit code = %d, want 42", exitErr.ExitCode())
		}
	} else {
		t.Fatalf("unexpected error type: %T: %v", err, err)
	}
}

func TestSandboxExecWorkingDirectory(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox exec test in short mode")
	}
	bin := requireSandboxExecBinary(t, t.TempDir())
	appDir := sbAppDir(t)

	cmd := exec.Command(bin, "--allow-unsafe-no-landlock", "--as-app", appDir, "--", "pwd")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("as-app failed: %v\nstderr: %s\nstdout: %s", err, stderr.String(), stdout.String())
	}
	got := strings.TrimSpace(stdout.String())
	if got != appDir {
		t.Fatalf("pwd = %q, want %q", got, appDir)
	}
}

func TestSandboxExecSourceReadOnly(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox exec test in short mode")
	}
	bin := requireSandboxExecBinary(t, t.TempDir())
	appDir := sbAppDir(t)

	// Source write should fail
	cmd := exec.Command(bin, "--allow-unsafe-no-landlock", "--as-app", appDir, "--", "touch", filepath.Join(appDir, "newfile.txt"))
	if err := cmd.Run(); err == nil {
		t.Fatal("expected source write to fail")
	} else if exitErr, ok := err.(*exec.ExitError); ok {
		if exitErr.ExitCode() == 0 {
			t.Fatal("source write succeeded unexpectedly")
		}
	}
}

func TestSandboxExecDataWritable(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox exec test in short mode")
	}
	bin := requireSandboxExecBinary(t, t.TempDir())
	appDir := sbAppDir(t)
	if err := os.MkdirAll(filepath.Join(appDir, "data"), 0o755); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(bin, "--allow-unsafe-no-landlock", "--as-app", appDir, "--", "touch", filepath.Join(appDir, "data", "wrote.txt"))
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("data write should succeed: %v\nstderr: %s", err, stderr.String())
	}
	if _, err := os.Stat(filepath.Join(appDir, "data", "wrote.txt")); os.IsNotExist(err) {
		t.Fatal("wrote.txt not created in data/")
	}
}

func TestSandboxExecInteractiveShellHomeNoUserRc(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sandbox exec test in short mode")
	}
	bin := requireSandboxExecBinary(t, t.TempDir())
	appDir := sbAppDir(t)

	cmd := exec.Command(bin, "--allow-unsafe-no-landlock", "--as-app", appDir, "--", "bash", "-i", "-c", "echo HOME=$HOME")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("as-app failed: %v\nstderr: %s\nstdout: %s", err, stderr.String(), stdout.String())
	}
	want := filepath.Join(appDir, "data")
	if got := strings.TrimSpace(stdout.String()); got != "HOME="+want {
		t.Fatalf("HOME = %q, want %q", got, "HOME="+want)
	}
	if strings.Contains(stderr.String(), "/.bashrc") {
		t.Fatalf("interactive shell touched a user rc file: %s", stderr.String())
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
