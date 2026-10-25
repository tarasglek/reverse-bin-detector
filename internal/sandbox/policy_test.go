package sandbox

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
)

func TestDetectionPolicy(t *testing.T) {
	p := DetectionPolicy("/apps/demo", map[string]string{"PATH": "/x:/y", "SOPS_AGE_KEY_FILE": "/keys/age.txt"})
	for _, want := range []string{"/apps/demo", "/dev/null", "/usr", "/x", "/y", "/keys/age.txt"} {
		assertContains(t, p.readOnly, want)
	}
	if !p.denyTCPConnect {
		t.Fatal("denyTCPConnect = false, want true")
	}
}

func TestRuntimePolicy(t *testing.T) {
	appDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(appDir, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	p := RuntimePolicy(appDir, false, "/run/sock")
	for _, want := range []string{"/bin", "/usr", "/lib", "/lib64", "/proc", "/sys/fs/cgroup", appDir} {
		assertContains(t, p.readOnlyExec, want)
	}
	for _, want := range []string{"/etc", "/sys"} {
		assertContains(t, p.readOnly, want)
	}
	for _, want := range []string{"/dev", filepath.Join(appDir, "data"), "/run/sock"} {
		assertContains(t, p.readWrite, want)
	}
	if !p.unrestrictedNetwork {
		t.Fatal("unrestrictedNetwork = false, want true")
	}

	static := RuntimePolicy(appDir, true, "/run/sock")
	assertNotContains(t, static.readOnly, "/sys")
	assertNotContains(t, static.readWrite, filepath.Join(appDir, "data"))
	if static.unrestrictedNetwork {
		t.Fatal("static unrestrictedNetwork = true, want false")
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
			p := runtimePolicy(app, tt.static, "", etcDir)
			if got := extraGrants(p.readOnly, "/etc", "/sys"); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("runtime extra read-only grants = %#v, want %#v", got, tt.want)
			}
			if tt.static {
				return
			}
			d := detectionPolicy(app, nil, etcDir)
			if got := extraGrants(d.readOnly, app, "/dev/null", "/bin", "/usr", "/lib", "/lib64", "/etc"); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("detection extra read-only grants = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestWithWritable(t *testing.T) {
	appDir := t.TempDir()
	base := RuntimePolicy(appDir, false, "")
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

func TestLandrunArgs(t *testing.T) {
	p := Policy{
		readOnlyExec:        []string{"/bin", "/usr"},
		readWriteExec:       []string{"/apps/demo"},
		readOnly:            []string{"/etc", "/run/systemd/resolve"},
		readWrite:           []string{"/dev"},
		unrestrictedNetwork: true,
	}
	want := []string{"--rox", "/bin", "--rox", "/usr", "--rwx", "/apps/demo", "--ro", "/etc", "--ro", "/run/systemd/resolve", "--rw", "/dev", "--unrestricted-network"}
	if got := LandrunArgs(p); !reflect.DeepEqual(got, want) {
		t.Fatalf("LandrunArgs = %#v, want %#v", got, want)
	}
	p.unrestrictedNetwork = false
	assertNotContains(t, LandrunArgs(p), "--unrestricted-network")
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
