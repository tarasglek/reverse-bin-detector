//go:build linux

package sandbox

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ll "github.com/landlock-lsm/go-landlock/landlock/syscall"
)

// TestLandrunRuntimePolicySurvivesResolvConfReplacement runs the rendered
// runtime policy through landrun and checks that the resolv.conf target stays
// readable after an atomic replace, as systemd-resolved performs.
func TestLandrunRuntimePolicySurvivesResolvConfReplacement(t *testing.T) {
	landrun, err := exec.LookPath("landrun")
	if err != nil {
		t.Skip("landrun not installed")
	}
	if abi, err := ll.LandlockGetABIVersion(); err != nil || abi < 1 {
		t.Skipf("landlock unsupported: abi %d, %v", abi, err)
	}

	appDir := t.TempDir()
	resolveDir := t.TempDir()
	target := filepath.Join(resolveDir, "stub-resolv.conf")
	writeSandboxTestFile(t, target, "nameserver 10.0.0.1\n")
	etcDir := t.TempDir()
	if err := os.Symlink(target, filepath.Join(etcDir, "resolv.conf")); err != nil {
		t.Fatal(err)
	}
	flag := filepath.Join(t.TempDir(), "replaced")

	p := runtimePolicy(appDir, false, "", etcDir)
	assertContains(t, p.readOnly, resolveDir)

	script := "cat " + target + " && while [ ! -e " + flag + " ]; do sleep 0.05; done && cat " + target
	args := append(LandrunArgs(p), "--", "/bin/sh", "-c", script)
	cmd := exec.Command(landrun, args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
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
