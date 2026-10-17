package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/tarasglek/caddy-reverse-bin/detectorschema"
)

func TestCLIPythonSocketAppOutput(t *testing.T) {
	appDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(appDir, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
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

func TestCLIPublicHost(t *testing.T) {
	appDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(appDir, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(appDir, "main.py"), []byte("#!/usr/bin/env python3\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	envs := *runDetectorOK(t, appDir, "--public-host=demo.example.test").Envs
	if !slices.Contains(envs, "REVERSE_BIN_PUBLIC_HOST=demo.example.test") {
		t.Fatalf("Envs missing REVERSE_BIN_PUBLIC_HOST: %#v", envs)
	}
	for _, env := range envs {
		if strings.HasPrefix(env, "REVERSE_BIN_PUBLIC_URL=") {
			t.Fatalf("Envs still contain %q", env)
		}
	}
	for _, env := range *runDetectorOK(t, appDir).Envs {
		if strings.HasPrefix(env, "REVERSE_BIN_PUBLIC_") {
			t.Fatalf("Envs without --public-host contain %q", env)
		}
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

// Caddy runs the detector exactly like this: Landlock detection sandbox and
// runtime sandbox on. An app without data/ must still get a plan, read-only.
func TestCLIAppWithoutDataPlansReadOnly(t *testing.T) {
	appDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(appDir, "main.ts"), []byte("export default {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "run", ".", appDir)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("detector refused app without data/: %v\n%s", err, out)
	}
	payload, err := detectorschema.Parse(out)
	if err != nil {
		t.Fatalf("schema parse failed: %v\n%s", err, out)
	}
	if got := strings.Join(*payload.Executable, " "); strings.Contains(got, "--rw "+filepath.Join(appDir, "data")) {
		t.Fatalf("plan grants write access to missing data/: %s", got)
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

func requireAsAppBinary(t *testing.T, binDir string) string {
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
	if err := os.Mkdir(filepath.Join(appDir, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(appDir, "main.py"), []byte("#!/usr/bin/env python3\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return appDir
}

func TestAsApp(t *testing.T) {
	bin := requireAsAppBinary(t, t.TempDir())
	run := func(appDir string, args ...string) (string, string, error) {
		cmd := exec.Command(bin, append([]string{"--as-app", appDir, "--"}, args...)...)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		err := cmd.Run()
		return stdout.String(), stderr.String(), err
	}

	t.Run("command and arguments", func(t *testing.T) {
		stdout, stderr, err := run(sbAppDir(t), "echo", "hello world")
		if err != nil {
			t.Fatalf("as-app failed: %v\nstderr: %s", err, stderr)
		}
		if got := strings.TrimSpace(stdout); got != "hello world" {
			t.Fatalf("stdout = %q, want hello world", got)
		}
	})

	t.Run("relative app path", func(t *testing.T) {
		root := t.TempDir()
		appDir := filepath.Join(root, "app")
		if err := os.Mkdir(appDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(appDir, "data"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(appDir, "main.py"), []byte("#!/usr/bin/env python3\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(bin, "--as-app", "app", "--", "pwd")
		cmd.Dir = root
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("as-app failed: %v\n%s", err, out)
		}
		if got := strings.TrimSpace(string(out)); got != appDir {
			t.Fatalf("pwd = %q, want %q", got, appDir)
		}
	})

	t.Run("exact environment", func(t *testing.T) {
		appDir := sbAppDir(t)
		if err := os.WriteFile(filepath.Join(appDir, ".env"), []byte("CUSTOM=secret\nREVERSE_BIN_PORT=7777\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		stdout, stderr, err := run(appDir, "sh", "-c", "printf '%s\\n' \"$CUSTOM\" \"$USER\" \"$HOME\"")
		if err != nil {
			t.Fatalf("as-app failed: %v\nstderr: %s", err, stderr)
		}
		want := "secret\n\n" + filepath.Join(appDir, "data") + "\n"
		if stdout != want {
			t.Fatalf("environment output = %q, want %q", stdout, want)
		}
	})

	t.Run("public host", func(t *testing.T) {
		cmd := exec.Command(bin, "--public-host=demo.localhost:9443", "--as-app", sbAppDir(t), "--", "sh", "-c", "printf '%s' \"$REVERSE_BIN_PUBLIC_HOST\"")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("as-app failed: %v\n%s", err, out)
		}
		if got, want := string(out), "demo.localhost:9443"; got != want {
			t.Fatalf("public host = %q, want %q", got, want)
		}
	})

	t.Run("exit status", func(t *testing.T) {
		_, _, err := run(sbAppDir(t), "sh", "-c", "exit 42")
		exitErr, ok := err.(*exec.ExitError)
		if !ok || exitErr.ExitCode() != 42 {
			t.Fatalf("error = %T %v, want exit code 42", err, err)
		}
	})

	t.Run("source read only", func(t *testing.T) {
		appDir := sbAppDir(t)
		_, _, err := run(appDir, "touch", filepath.Join(appDir, "newfile.txt"))
		if _, ok := err.(*exec.ExitError); !ok {
			t.Fatalf("error = %T %v, want denied command exit", err, err)
		}
	})

	t.Run("data writable", func(t *testing.T) {
		appDir := sbAppDir(t)
		dataDir := filepath.Join(appDir, "data")
		path := filepath.Join(dataDir, "wrote.txt")
		if _, stderr, err := run(appDir, "touch", path); err != nil {
			t.Fatalf("data write failed: %v\nstderr: %s", err, stderr)
		}
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("stat written file: %v", err)
		}
	})

	t.Run("no data directory runs read-only", func(t *testing.T) {
		appDir := sbAppDir(t)
		if err := os.Remove(filepath.Join(appDir, "data")); err != nil {
			t.Fatal(err)
		}
		stdout, stderr, err := run(appDir, "sh", "-c", "head -c2 main.py && ! touch new.txt 2>/dev/null")
		if err != nil || stdout != "#!" {
			t.Fatalf("as-app without data: %v\nstdout: %q\nstderr: %s", err, stdout, stderr)
		}
	})

	t.Run("hangup leaves no sandbox behind", func(t *testing.T) {
		// A unique sleep duration identifies this test's sandboxed process.
		duration := fmt.Sprintf("3600.%06d", os.Getpid())
		pattern := "^sleep " + regexp.QuoteMeta(duration) + "$"
		t.Cleanup(func() { _ = exec.Command("pkill", "-KILL", "-f", pattern).Run() })

		cmd := exec.Command(bin, "--as-app", sbAppDir(t), "--", "sleep", duration)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		if !waitFor(func() bool { return exec.Command("pgrep", "-f", pattern).Run() == nil }) {
			t.Fatal("sandboxed sleep never started")
		}
		if err := cmd.Process.Signal(syscall.SIGHUP); err != nil {
			t.Fatal(err)
		}
		_ = cmd.Wait()
		if !waitFor(func() bool { return exec.Command("pgrep", "-f", pattern).Run() != nil }) {
			t.Fatal("sandboxed process survived SIGHUP to --as-app")
		}
	})

	t.Run("interactive home", func(t *testing.T) {
		appDir := sbAppDir(t)
		stdout, stderr, err := run(appDir, "bash", "-i", "-c", "echo HOME=$HOME")
		if err != nil {
			t.Fatalf("as-app failed: %v\nstderr: %s", err, stderr)
		}
		want := "HOME=" + filepath.Join(appDir, "data")
		if got := strings.TrimSpace(stdout); got != want {
			t.Fatalf("HOME = %q, want %q", got, want)
		}
		if strings.Contains(stderr, "/.bashrc") {
			t.Fatalf("interactive shell touched a user rc file: %s", stderr)
		}
	})
}

func waitFor(cond func() bool) bool {
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if cond() {
			return true
		}
	}
	return false
}

func runDetectorOK(t *testing.T, appDir string, flags ...string) *detectorschema.DetectorOutput {
	t.Helper()
	args := append([]string{"run", ".", "--allow-unsafe-no-landlock", "--no-runtime-sandbox"}, flags...)
	cmd := exec.Command("go", append(args, appDir)...)
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
