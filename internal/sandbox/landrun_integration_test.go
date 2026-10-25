//go:build linux

package sandbox

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestLandrunRuntimePolicySurvivesResolvConfReplacement runs the rendered
// runtime policy through landrun and checks that the resolv.conf target stays
// readable after an atomic replace, as systemd-resolved performs.
func TestLandrunRuntimePolicySurvivesResolvConfReplacement(t *testing.T) {
	requireLandrun(t)

	appDir := t.TempDir()
	resolveDir := t.TempDir()
	target := filepath.Join(resolveDir, "stub-resolv.conf")
	writeSandboxTestFile(t, target, "nameserver 10.0.0.1\n")
	etcDir := t.TempDir()
	if err := os.Symlink(target, filepath.Join(etcDir, "resolv.conf")); err != nil {
		t.Fatal(err)
	}
	flag := filepath.Join(t.TempDir(), "replaced")

	p := mustRuntimePolicy(t, appDir, false, "", etcDir)
	assertContains(t, p.readOnly, resolveDir)

	script := "cat " + target + " && while [ ! -e " + flag + " ]; do sleep 0.05; done && cat " + target
	argv := Command(p, nil, []string{"/bin/sh", "-c", script})
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	done := make(chan struct{})
	var out []byte
	var runErr error
	go func() {
		defer close(done)
		out, runErr = cmd.CombinedOutput()
	}()

	time.Sleep(300 * time.Millisecond)
	tmp := filepath.Join(resolveDir, ".stub-resolv.conf.tmp")
	writeSandboxTestFile(t, tmp, "nameserver 10.0.0.2\n")
	if err := os.Rename(tmp, target); err != nil {
		t.Fatal(err)
	}
	writeSandboxTestFile(t, flag, "")

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		<-done
		t.Fatalf("landrun did not finish; output:\n%s", out)
	}
	if runErr != nil {
		t.Fatalf("landrun failed: %v\n%s", runErr, out)
	}
	want := "nameserver 10.0.0.1\nnameserver 10.0.0.2\n"
	if got := string(out); got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
	if strings.Contains(string(out), "denied") {
		t.Fatalf("output contains denial: %q", out)
	}
}

// TestLandrunCommand checks Command against the real landrun: app flags after
// -- reach the app, env values arrive by name, and the sandbox is enforced.
func TestLandrunCommand(t *testing.T) {
	requireLandrun(t)
	outside := filepath.Join(t.TempDir(), "escape")
	p := Policy{readOnlyExec: []string{"/bin", "/usr", "/lib", "/lib64"}}
	script := `printf '%s %s' "$1" "$SECRET"; touch "$2" || true`
	argv := Command(p, []string{"SECRET"}, []string{"/bin/sh", "-c", script, "sh", "--rw", outside})
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "SECRET=s3cret"}
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("landrun failed: %v\n%s", err, out)
	}
	if got := string(out); got != "--rw s3cret" {
		t.Fatalf("output = %q, want %q", got, "--rw s3cret")
	}
	if _, err := os.Stat(outside); err == nil {
		t.Fatal("sandboxed command wrote outside its grants")
	}
}

func requireLandrun(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("landrun"); err != nil {
		t.Skip("landrun not installed")
	}
	if err := RequireLandlock(); err != nil {
		t.Skip(err)
	}
}
