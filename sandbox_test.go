package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestSOPSPolicy(t *testing.T) {
	p := SOPSPolicy("/opt/sops", "/keys/age.txt")
	assertContains(t, p.readOnlyExec, "/opt/sops")
	assertContains(t, p.readOnly, "/keys/age.txt")
	if p.unrestrictedNetwork || len(p.readWrite) > 0 || len(p.readWriteExec) > 0 {
		t.Fatalf("SOPSPolicy grants network or writes: %#v", p)
	}
	if len(p.unix) > 0 {
		t.Fatalf("SOPSPolicy unix = %#v, want no socket", p.unix)
	}
	if got := SOPSPolicy("/opt/sops", ""); len(got.readOnly) != 1 {
		t.Fatalf("readOnly without key = %#v, want only /etc", got.readOnly)
	}
}

func TestRuntimePolicyRejectsSymlinkedData(t *testing.T) {
	appDir := t.TempDir()
	if err := os.Symlink(t.TempDir(), filepath.Join(appDir, "data")); err != nil {
		t.Fatal(err)
	}
	if _, err := RuntimePolicy(appDir, false, ""); err == nil {
		t.Fatal("symlinked data accepted")
	}
}

func TestRuntimePolicy(t *testing.T) {
	appDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(appDir, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	p := mustRuntimePolicy(t, appDir, false, "/run/sock", "/etc")
	for _, want := range []string{"/bin", "/usr", "/lib", "/lib64", "/proc", "/sys/fs/cgroup", appDir} {
		assertContains(t, p.readOnlyExec, want)
	}
	for _, want := range []string{"/etc", "/sys"} {
		assertContains(t, p.readOnly, want)
	}
	for _, want := range []string{"/dev", "/run/sock"} {
		assertContains(t, p.readWrite, want)
	}
	assertContains(t, p.readWriteExec, filepath.Join(appDir, "data"))
	assertNotContains(t, p.readWrite, filepath.Join(appDir, "data"))
	if !p.unrestrictedNetwork {
		t.Fatal("unrestrictedNetwork = false, want true")
	}

	static := mustRuntimePolicy(t, appDir, true, "/run/sock", "/etc")
	assertNotContains(t, static.readOnly, "/sys")
	assertNotContains(t, static.readWrite, filepath.Join(appDir, "data"))
	assertNotContains(t, static.readWriteExec, filepath.Join(appDir, "data"))
	if static.unrestrictedNetwork {
		t.Fatal("static unrestrictedNetwork = true, want false")
	}
	if len(static.unix) > 0 {
		t.Fatalf("static unix = %#v, want no socket", static.unix)
	}
}

func TestEtcSymlinkGrants(t *testing.T) {
	appDir := t.TempDir()
	targetDir := t.TempDir()
	target := filepath.Join(targetDir, "stub-resolv.conf")
	writeSandboxTestFile(t, target, "nameserver 127.0.0.53\n")
	// Explicit /tmp so the parent is exactly a broadDirs entry regardless of $TMPDIR.
	tmpFile, err := os.CreateTemp("/tmp", "sandbox-broad-*")
	if err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()
	t.Cleanup(func() { os.Remove(tmpFile.Name()) })

	tests := []struct {
		name   string
		appDir string // defaults to appDir
		link   string // symlink target; "" means regular file
		static bool
		want   []string
	}{
		{name: "sibling of app dir adds parent", link: target, want: []string{targetDir}},
		{name: "regular file adds nothing"},
		{name: "symlink into /usr adds nothing", link: "/usr/share/zoneinfo/UTC"},
		{name: "broken symlink adds nothing", link: filepath.Join(targetDir, "missing")},
		// appDir must not be under /tmp, or the app-dir guard would refuse it first.
		{name: "broad parent refused", appDir: "/apps/demo", link: tmpFile.Name()},
		{name: "app dir ancestor refused", appDir: filepath.Join(targetDir, "app"), link: target},
		{name: "static app adds nothing", link: target, static: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := tt.appDir
			if app == "" {
				app = appDir
			}
			etcDir := t.TempDir()
			resolv := filepath.Join(etcDir, "resolv.conf")
			if tt.link == "" {
				writeSandboxTestFile(t, resolv, "nameserver 127.0.0.53\n")
			} else if err := os.Symlink(tt.link, resolv); err != nil {
				t.Fatal(err)
			}
			p := mustRuntimePolicy(t, app, tt.static, "", etcDir)
			if got := extraGrants(p.readOnly, "/etc", "/sys"); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("runtime extra read-only grants = %#v, want %#v", got, tt.want)
			}
			// Unix connects: the app's own sockets and the resolver's, nothing else.
			if wantUnix := append([]string{app}, tt.want...); !tt.static && !reflect.DeepEqual(p.unix, wantUnix) {
				t.Fatalf("unix grants = %#v, want %#v", p.unix, wantUnix)
			}
		})
	}
}

func TestWithWritable(t *testing.T) {
	appDir := t.TempDir()
	base := mustRuntimePolicy(t, appDir, false, "", "/etc")
	p := base.WithWritable(appDir)
	assertNotContains(t, p.readOnlyExec, appDir)
	if !reflect.DeepEqual(p.readWriteExec, []string{appDir}) {
		t.Fatalf("readWriteExec = %#v, want [%q]", p.readWriteExec, appDir)
	}
	if !reflect.DeepEqual(p.readOnly, base.readOnly) || !reflect.DeepEqual(p.readWrite, base.readWrite) || p.unrestrictedNetwork != base.unrestrictedNetwork {
		t.Fatalf("WithWritable changed other grants: %#v, base %#v", p, base)
	}
	if !reflect.DeepEqual(extraGrants(base.readOnlyExec, p.readOnlyExec...), []string{appDir}) {
		t.Fatalf("readOnlyExec = %#v, want base %#v without %q", p.readOnlyExec, base.readOnlyExec, appDir)
	}
	assertContains(t, base.readOnlyExec, appDir)
}

// TestCommand: strict landrun (no --best-effort), env by name, the command
// after --; --unix only where the kernel enforces it.
func TestCommand(t *testing.T) {
	got := Command(Policy{readOnly: []string{"/etc"}}, []string{"A", "B"}, []string{"app", "--rw", "/"})
	want := []string{"landrun", "--ro", "/etc", "--env", "A", "--env", "B", "--", "app", "--rw", "/"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Command = %#v, want %#v", got, want)
	}
	// The unix grants reach landrun exactly from UnixABI; below it strict
	// landrun would refuse them.
	p := Policy{readOnly: []string{"/etc"}, unix: []string{"/apps/demo", "/run/systemd/resolve"}}
	for abi, want := range map[int][]string{
		UnixABI - 1: {"landrun", "--ro", "/etc", "--", "app"},
		UnixABI:     {"landrun", "--ro", "/etc", "--unix", "/apps/demo", "--unix", "/run/systemd/resolve", "--", "app"},
	} {
		if got := commandFor(abi, p, nil, []string{"app"}); !reflect.DeepEqual(got, want) {
			t.Fatalf("Command on ABI %d = %#v, want %#v", abi, got, want)
		}
	}
}

func TestLandrunArgs(t *testing.T) {
	p := Policy{
		readOnlyExec:        []string{"/bin", "/usr"},
		readWriteExec:       []string{"/apps/demo"},
		readOnly:            []string{"/etc", "/run/systemd/resolve"},
		readWrite:           []string{"/dev"},
		unix:                []string{"/apps/demo"},
		unrestrictedNetwork: true,
		bindTCP:             []string{"0", "9001", "9229"},
	}
	want := []string{"--rox", "/bin", "--rox", "/usr", "--rwx", "/apps/demo", "--ro", "/etc", "--ro", "/run/systemd/resolve", "--rw", "/dev",
		"--unix", "/apps/demo", "--unrestricted-network", "--bind-tcp", "0", "--bind-tcp", "9001", "--bind-tcp", "9229"}
	if got := landrunArgs(p); !reflect.DeepEqual(got, want) {
		t.Fatalf("landrunArgs = %#v, want %#v", got, want)
	}
	p.unrestrictedNetwork, p.bindTCP = false, nil
	assertNotContains(t, landrunArgs(p), "--unrestricted-network")
	assertNotContains(t, landrunArgs(p), "--bind-tcp")
}

// extraGrants returns values not in the baseline, preserving order.
func extraGrants(values []string, baseline ...string) []string {
	var extra []string
	for _, value := range values {
		if !slices.Contains(baseline, value) {
			extra = append(extra, value)
		}
	}
	return extra
}

func assertContains(t *testing.T, values []string, want string) {
	t.Helper()
	if slices.Contains(values, want) {
		return
	}
	t.Fatalf("%q not in %#v", want, values)
}

func writeSandboxTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func assertNotContains(t *testing.T, values []string, unwanted string) {
	t.Helper()
	for _, value := range values {
		if value == unwanted {
			t.Fatalf("%q unexpectedly in %#v", unwanted, values)
		}
	}
}

func mustRuntimePolicy(t *testing.T, appDir string, static bool, socketDir, etcDir string) Policy {
	t.Helper()
	p, err := runtimePolicy(appDir, static, socketDir, etcDir)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

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
	var stderr bytes.Buffer
	cmd.Stderr = &stderr // landrun warns there about what this kernel cannot enforce
	go func() {
		defer close(done)
		out, runErr = cmd.Output()
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

// TestLandrunRuntimePolicyAllowsWriteThenExecInData pins the contract that an
// app can install and run a binary in data/ while its source stays read-only.
// TestRuntimePolicy pins the explicit --rwx flag itself.
func TestLandrunRuntimePolicyAllowsWriteThenExecInData(t *testing.T) {
	requireLandrun(t)
	appDir := t.TempDir()
	data := filepath.Join(appDir, "data")
	if err := os.Mkdir(data, 0o755); err != nil {
		t.Fatal(err)
	}
	p := mustRuntimePolicy(t, appDir, false, "", "/etc")

	bin := filepath.Join(data, "tool")
	script := "printf '#!/bin/sh\\necho ran\\n' > " + bin + " && chmod +x " + bin + " && " + bin +
		" && ! touch " + filepath.Join(appDir, "src") + " 2>/dev/null && echo src-ro"
	argv := Command(p, nil, []string{"/bin/sh", "-c", script})
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr // landrun warns there about what this kernel cannot enforce
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("landrun failed: %v\n%s", err, stderr.Bytes())
	}
	if got, want := string(out), "ran\nsrc-ro\n"; got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
}
