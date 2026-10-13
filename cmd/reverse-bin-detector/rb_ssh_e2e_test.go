package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// buildRBSSH builds the detector with a test apps root and returns an rb-ssh
// symlink to it, mirroring the package layout.
func buildRBSSH(t *testing.T, appsRoot string) string {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "reverse-bin-detector")
	ldflags := "-X main.sshAppsRoot=" + appsRoot + " -X main.sshPath=" + os.Getenv("PATH")
	out, err := exec.Command("go", "build", "-ldflags", ldflags, "-o", bin, ".").CombinedOutput()
	if err != nil {
		t.Fatalf("build rb-ssh: %v\n%s", err, out)
	}
	link := filepath.Join(dir, "rb-ssh")
	if err := os.Symlink("reverse-bin-detector", link); err != nil {
		t.Fatal(err)
	}
	return link
}

func TestRBSSH(t *testing.T) {
	appsRoot := t.TempDir()
	appDir := filepath.Join(appsRoot, "todo")
	if err := os.Mkdir(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(appDir, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(appDir, "main.py"), []byte("#!/usr/bin/env python3\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	bin := buildRBSSH(t, appsRoot)

	run := func(stdin string, env []string, args ...string) (string, string, error) {
		cmd := exec.Command(bin, args...)
		cmd.Env = append([]string{"PATH=/nonexistent", "TERM=xterm-test"}, env...)
		cmd.Stdin = strings.NewReader(stdin)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		err := cmd.Run()
		return stdout.String(), stderr.String(), err
	}

	t.Run("one-shot command as forced-command shell", func(t *testing.T) {
		stdout, stderr, err := run("", []string{"SSH_ORIGINAL_COMMAND=printf '%s\\n' \"$HOME\" \"$TERM\" \"$PWD\"; exit 3"},
			"-c", "/usr/lib/reverse-bin/rb-ssh todo")
		exitErr, ok := err.(*exec.ExitError)
		if !ok || exitErr.ExitCode() != 3 {
			t.Fatalf("error = %T %v, want exit 3\nstderr: %s", err, err, stderr)
		}
		want := filepath.Join(appDir, "data") + "\nxterm-test\n" + appDir + "\n"
		if stdout != want {
			t.Fatalf("stdout = %q, want %q", stdout, want)
		}
	})

	t.Run("interactive shell", func(t *testing.T) {
		stdout, stderr, err := run("echo marker-$HOME\n", nil, "todo")
		if err != nil {
			t.Fatalf("rb-ssh failed: %v\nstderr: %s", err, stderr)
		}
		if want := "marker-" + filepath.Join(appDir, "data"); !strings.Contains(stdout, want) {
			t.Fatalf("stdout = %q, want %q", stdout, want)
		}
	})

	t.Run("source read only", func(t *testing.T) {
		_, _, err := run("", []string{"SSH_ORIGINAL_COMMAND=touch " + filepath.Join(appDir, "x")}, "todo")
		if _, ok := err.(*exec.ExitError); !ok {
			t.Fatalf("error = %T %v, want denied write", err, err)
		}
	})

	t.Run("refusals", func(t *testing.T) {
		for name, args := range map[string][]string{
			"general shell": {"-c", "bash"},
			"missing app":   {"nope"},
			"traversal":     {".."},
			"sftp":          {"todo"},
		} {
			env := []string{}
			if name == "sftp" {
				env = append(env, "SSH_ORIGINAL_COMMAND=/usr/lib/openssh/sftp-server")
			}
			_, stderr, err := run("", env, args...)
			if err == nil || !strings.Contains(stderr, "rb-ssh:") {
				t.Fatalf("%s: error = %v, stderr = %q, want rb-ssh refusal", name, err, stderr)
			}
		}
	})

	t.Run("sandbox dies with its sshd parent", func(t *testing.T) {
		// Without a PTY sshd sends no hangup on disconnect; its session process just exits.
		duration := fmt.Sprintf("3600.%d", time.Now().UnixNano())
		pattern := "^sleep " + regexp.QuoteMeta(duration) + "$"
		t.Cleanup(func() { _ = exec.Command("pkill", "-KILL", "-f", pattern).Run() })

		parent := exec.Command("sh", "-c", `"$0" todo; :`, bin)
		parent.Env = []string{"SSH_ORIGINAL_COMMAND=sleep " + duration}
		if err := parent.Start(); err != nil {
			t.Fatal(err)
		}
		if !waitFor(func() bool { return exec.Command("pgrep", "-f", pattern).Run() == nil }) {
			t.Fatal("sandboxed sleep never started")
		}
		if err := parent.Process.Kill(); err != nil {
			t.Fatal(err)
		}
		_ = parent.Wait()
		if !waitFor(func() bool { return exec.Command("pgrep", "-f", pattern).Run() != nil }) {
			t.Fatal("sandbox survived its parent")
		}
	})

	t.Run("login shell refused", func(t *testing.T) {
		cmd := exec.Command(bin)
		cmd.Args[0] = "-rb-ssh"
		out, err := cmd.CombinedOutput()
		if err == nil || !strings.Contains(string(out), "command=") {
			t.Fatalf("error = %v, output = %q, want login refusal", err, out)
		}
	})
}
