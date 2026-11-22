package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"
)

// buildBinary builds the detector as packaged, with test paths, and returns
// it plus an rb-ssh symlink to it.
func buildBinary(t *testing.T, appsRoot string) (bin, rbssh string) {
	t.Helper()
	requireLandrun(t)
	dir := t.TempDir()
	bin = filepath.Join(dir, "reverse-bin-detector")
	ldflags := "-X main.staticRoot=" + t.TempDir() + " -X main.sshAppsRoot=" + appsRoot + " -X main.sshPath=" + os.Getenv("PATH")
	if out, err := exec.Command("go", "build", "-ldflags", ldflags, "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	rbssh = filepath.Join(dir, "rb-ssh")
	if err := os.Symlink("reverse-bin-detector", rbssh); err != nil {
		t.Fatal(err)
	}
	return bin, rbssh
}

// waitFor polls cond for up to 30s: servers and sandboxes start
// asynchronously.
func waitFor(cond func() bool) bool {
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if cond() {
			return true
		}
	}
	return false
}

// TestKindsServeHTTP runs the App the detector emits for each kind, as
// reverse_bin would (sandboxed, exact env, app dir), GETs / from its dial,
// and stops it with SIGTERM.
func TestKindsServeHTTP(t *testing.T) {
	bin, _ := buildBinary(t, t.TempDir())
	if _, err := os.Stat("/usr/lib/reverse-bin/deno"); err == nil {
		t.Setenv("PATH", "/usr/lib/reverse-bin:"+os.Getenv("PATH"))
	}
	py := "#!/usr/bin/env python3\nimport http.server, os, socketserver\nclass S(socketserver.UnixStreamServer):\n    def get_request(self):\n        r, _ = super().get_request()\n        return r, ('local', 0)\nS(os.environ['SOCKET_PATH'], http.server.SimpleHTTPRequestHandler).serve_forever()\n"
	for name, files := range map[string]map[string]string{
		"explicit": {".env": "REVERSE_BIN_COMMAND=exec python3 -m http.server \"$REVERSE_BIN_PORT\" --bind \"$REVERSE_BIN_HOST\"\n", "data/.keep": ""},
		"python":   {"main.py*": py, "data/.keep": ""},
		"deno":     {"main.ts": "export default { fetch: () => new Response('ok') };\n", "data/.keep": ""},
		"static":   {"index.html": "<h1>ok</h1>\n"},
		"explicit on a stale socket": {
			".env":       "REVERSE_BIN_COMMAND=exec reverse-bin-caddy file-server --listen \"unix/$SOCKET_PATH\" --root .\nSOCKET_PATH=data/s.sock\n",
			"index.html": "ok\n", "data/.keep": "",
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := exec.LookPath("deno"); name == "deno" && err != nil {
				t.Skip("deno not installed")
			}
			// Static apps and the stale-socket case are served by the packaged Caddy.
			if _, err := exec.LookPath("reverse-bin-caddy"); (name == "static" || name == "explicit on a stale socket") && err != nil {
				t.Skip("reverse-bin-caddy not installed")
			}
			dir := appDir(t, files)
			if name == "explicit on a stale socket" {
				l, err := net.Listen("unix", filepath.Join(dir, "data/s.sock"))
				if err != nil {
					t.Fatal(err)
				}
				l.(*net.UnixListener).SetUnlinkOnClose(false)
				l.Close() // a previous instance's socket, left behind
			}
			out, err := exec.Command(bin, dir).Output()
			var a App
			if err == nil {
				err = json.Unmarshal(out, &a)
			}
			if err != nil {
				t.Fatalf("detector: %v\n%s", err, out)
			}
			cmd := exec.Command(a.Executable[0], a.Executable[1:]...)
			cmd.Dir, cmd.Env, cmd.SysProcAttr = a.WorkingDirectory, a.Envs, &syscall.SysProcAttr{Setpgid: true}
			var logs bytes.Buffer
			cmd.Stdout, cmd.Stderr = &logs, &logs
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) })
			network, address := "tcp", a.ReverseProxyTo
			if strings.HasPrefix(a.ReverseProxyTo, "unix/") {
				network, address = "unix", a.ReverseProxyTo[5:]
			}
			client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return new(net.Dialer).DialContext(ctx, network, address)
			}}}
			// GET / through the app's dial address: it must serve 200.
			ok := waitFor(func() bool {
				resp, err := client.Get("http://app/")
				if err != nil {
					return false
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				return resp.StatusCode == http.StatusOK
			})
			if !ok {
				t.Fatalf("no 200 from %s; app output:\n%s", a.ReverseProxyTo, logs.String())
			}
			if name == "deno" {
				return // deno serve --watch ignores SIGTERM; reverse_bin SIGKILLs it after its grace
			}
			// SIGTERM to the group, as reverse_bin stops apps: none of these
			// installs a handler, so it works only if the app is not PID 1.
			done := make(chan struct{})
			go func() { _ = cmd.Wait(); close(done) }()
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("app ignored SIGTERM")
			}
		})
	}
}

// TestAsApp checks --as-app and --as-app-dev: the command runs in the app's
// sandbox with exactly its env, source read-only (writable with -dev), data/
// writable, the exit status kept, and no sandbox left after a hangup.
func TestAsApp(t *testing.T) {
	bin, _ := buildBinary(t, t.TempDir())
	app := func() string {
		return appDir(t, map[string]string{"main.py*": "#!/usr/bin/env python3\n", "data/.keep": "", ".env": "CUSTOM=secret\n"})
	}
	run := func(mode, dir string, args ...string) (string, error) {
		out, err := exec.Command(bin, append([]string{mode, dir, "--"}, args...)...).Output()
		return string(out), err
	}
	dir := app()
	if out, err := run("--as-app", dir, "sh", "-c", `printf '%s|%s|%s|%s' "$CUSTOM" "$USER" "$HOME" "$PWD"`); err != nil || out != "secret||"+filepath.Join(dir, "data")+"|"+dir {
		t.Errorf("env and dir: %q %v", out, err)
	}
	if _, err := run("--as-app", app(), "sh", "-c", "exit 42"); err == nil || err.(*exec.ExitError).ExitCode() != 42 {
		t.Errorf("exit status: %v, want 42", err)
	}
	dir = app()
	if _, err := run("--as-app", dir, "touch", filepath.Join(dir, "src")); err == nil {
		t.Error("--as-app wrote the source")
	}
	if _, err := run("--as-app", dir, "touch", filepath.Join(dir, "data/x")); err != nil {
		t.Errorf("--as-app could not write data/: %v", err)
	}
	if _, err := run("--as-app-dev", dir, "touch", filepath.Join(dir, "src")); err != nil {
		t.Errorf("--as-app-dev could not write the source: %v", err)
	}
	// A unique sleep duration identifies this test's sandboxed process.
	pattern := "^sleep " + regexp.QuoteMeta(fmt.Sprintf("3600.%06d", os.Getpid())) + "$"
	t.Cleanup(func() { _ = exec.Command("pkill", "-KILL", "-f", pattern).Run() })
	cmd := exec.Command(bin, "--as-app", app(), "--", "sleep", fmt.Sprintf("3600.%06d", os.Getpid()))
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	if !waitFor(func() bool { return exec.Command("pgrep", "-f", pattern).Run() == nil }) {
		t.Fatal("sandboxed sleep never started")
	}
	_ = cmd.Process.Signal(syscall.SIGHUP)
	_ = cmd.Wait()
	if !waitFor(func() bool { return exec.Command("pgrep", "-f", pattern).Run() != nil }) {
		t.Fatal("sandbox survived SIGHUP to --as-app")
	}
}

// TestRBSSH runs rb-ssh as sshd would: a one-shot command in the app's dev
// sandbox with PATH compiled in, git push updating the checkout, refusals,
// and the sandbox dying with its sshd parent.
func TestRBSSH(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "todo")
	writeFile(t, filepath.Join(dir, "main.py"), "#!/usr/bin/env python3\n", 0o755)
	writeFile(t, filepath.Join(dir, "data/.keep"), "", 0o644)
	_, rbssh := buildBinary(t, root)
	run := func(env []string, args ...string) (string, string, error) {
		cmd := exec.Command(rbssh, args...)
		cmd.Env = append([]string{"PATH=/nonexistent", "TERM=xterm-test"}, env...)
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		return stdout.String(), stderr.String(), err
	}
	stdout, stderr, err := run([]string{`SSH_ORIGINAL_COMMAND=printf '%s\n' "$HOME" "$TERM" "$PWD"; exit 3`}, "-c", "/usr/lib/reverse-bin/rb-ssh todo")
	if err == nil || err.(*exec.ExitError).ExitCode() != 3 || stdout != filepath.Join(dir, "data")+"\nxterm-test\n"+dir+"\n" {
		t.Errorf("one-shot: %q %v\n%s", stdout, err, stderr)
	}
	for name, args := range map[string][]string{"general shell": {"-c", "bash"}, "missing app": {"nope"}, "traversal": {".."}} {
		if _, stderr, err := run(nil, args...); err == nil || !strings.Contains(stderr, "rb-ssh:") {
			t.Errorf("%s: %v %q, want rb-ssh refusal", name, err, stderr)
		}
	}

	// git push over a stand-in for ssh updates the checkout (source writable).
	sshStub := filepath.Join(t.TempDir(), "ssh")
	writeFile(t, sshStub, "#!/bin/sh\nshift\nSSH_ORIGINAL_COMMAND=\"$*\" exec "+rbssh+" todo\n", 0o755)
	git := func(at string, args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = at
		cmd.Env = append(os.Environ(), "GIT_SSH_COMMAND="+sshStub, "GIT_CONFIG_GLOBAL=/dev/null", "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	git(dir, "init", "-q", "-b", "main")
	git(dir, "config", "receive.denyCurrentBranch", "updateInstead")
	git(dir, "add", "main.py")
	git(dir, "commit", "-q", "-m", "init")
	clone := filepath.Join(t.TempDir(), "clone")
	git("", "clone", "-q", dir, clone)
	writeFile(t, filepath.Join(clone, "pushed.txt"), "pushed\n", 0o644)
	git(clone, "add", "pushed.txt")
	git(clone, "commit", "-q", "-m", "push")
	git(clone, "-c", "ssh.variant=simple", "push", "-q", "reverse-bin@host:.", "main")
	if got, err := os.ReadFile(filepath.Join(dir, "pushed.txt")); err != nil || string(got) != "pushed\n" {
		t.Errorf("pushed.txt = %q, %v", got, err)
	}

	// Without a PTY sshd sends no hangup on disconnect; its session process just exits.
	duration := fmt.Sprintf("3600.%d", time.Now().UnixNano())
	pattern := "^sleep " + regexp.QuoteMeta(duration) + "$"
	t.Cleanup(func() { _ = exec.Command("pkill", "-KILL", "-f", pattern).Run() })
	parent := exec.Command("sh", "-c", `"$0" todo; :`, rbssh)
	parent.Env = []string{"SSH_ORIGINAL_COMMAND=sleep " + duration}
	if err := parent.Start(); err != nil {
		t.Fatal(err)
	}
	if !waitFor(func() bool { return exec.Command("pgrep", "-f", pattern).Run() == nil }) {
		t.Fatal("sandboxed sleep never started")
	}
	_ = parent.Process.Kill()
	_ = parent.Wait()
	if !waitFor(func() bool { return exec.Command("pgrep", "-f", pattern).Run() != nil }) {
		t.Fatal("sandbox survived its sshd parent")
	}
}

// TestVersion pins the --version format hosting's runtime check parses:
// "VERSION COMMIT DATE", the version first.
func TestVersion(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "d")
	if out, err := exec.Command("go", "build", "-ldflags", "-X main.version=1.2.3", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	if out, err := exec.Command(bin, "--version").Output(); err != nil || string(out) != "1.2.3 unknown unknown\n" {
		t.Fatalf("--version = %q, %v", out, err)
	}
}
