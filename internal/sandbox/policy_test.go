package sandbox

import (
	"reflect"
	"testing"
)

func TestDetectionPolicy(t *testing.T) {
	p := DetectionPolicy("/apps/demo", map[string]string{"SOPS_AGE_KEY_FILE": "/keys/age.txt"})
	assertContains(t, p.ReadOnly, "/apps/demo")
	assertContains(t, p.ReadOnly, "/usr")
	assertContains(t, p.ReadOnly, "/keys/age.txt")
	if len(p.ReadWrite) != 0 {
		t.Fatalf("ReadWrite = %#v, want none", p.ReadWrite)
	}
	if !p.AllowTCPBind || !p.DenyTCPConnect {
		t.Fatalf("flags = bind %v deny connect %v", p.AllowTCPBind, p.DenyTCPConnect)
	}
}

func TestPythonRuntimePolicy(t *testing.T) {
	p := PythonRuntimePolicy("/apps/demo", Transport{Kind: "tcp"})
	assertContains(t, p.ReadOnly, "/apps/demo")
	assertContains(t, p.ReadWrite, "/apps/demo/data")
	if !p.AllowTCPBind || !p.DenyTCPConnect {
		t.Fatalf("flags = bind %v deny connect %v", p.AllowTCPBind, p.DenyTCPConnect)
	}
}

func TestDenoRuntimePolicy(t *testing.T) {
	p := DenoRuntimePolicy("/apps/demo", "/usr/bin/deno", "/cache/deno", Transport{Kind: "tcp"})
	assertContains(t, p.ReadOnly, "/apps/demo")
	assertContains(t, p.ReadOnly, "/usr/bin/deno")
	assertContains(t, p.ReadOnly, "/cache/deno")
	assertContains(t, p.ReadWrite, "/apps/demo/data")
	if !p.AllowTCPBind {
		t.Fatal("AllowTCPBind = false, want true")
	}
	if p.DenyTCPConnect {
		t.Fatal("DenyTCPConnect = true, want false for current Smallweb-compatible Deno policy")
	}
}

func TestStaticPolicy(t *testing.T) {
	p := StaticPolicy("/apps/demo/dist")
	if !reflect.DeepEqual(p.ReadOnly, []string{"/apps/demo/dist"}) {
		t.Fatalf("ReadOnly = %#v", p.ReadOnly)
	}
	if len(p.ReadWrite) != 0 || p.AllowTCPBind || p.DenyTCPConnect {
		t.Fatalf("unexpected policy: %#v", p)
	}
}

func TestDenoServeArgs(t *testing.T) {
	got := DenoServeArgs("127.0.0.1", "8080", "main.ts")
	want := []string{"deno", "serve", "--watch", "--allow-all", "--host", "127.0.0.1", "--port", "8080", "main.ts"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("DenoServeArgs = %#v, want %#v", got, want)
	}
}

func assertContains(t *testing.T, values []string, want string) {
	t.Helper()
	for _, value := range values {
		if value == want {
			return
		}
	}
	t.Fatalf("%#v does not contain %q", values, want)
}
