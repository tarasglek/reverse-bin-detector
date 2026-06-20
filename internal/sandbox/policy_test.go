package sandbox

import "testing"

func TestDetectionPolicy(t *testing.T) {
	p := detectionPolicy("/apps/demo", map[string]string{"PATH": "/x:/y", "SOPS_AGE_KEY_FILE": "/keys/age.txt"})
	for _, want := range []string{"/apps/demo", "/dev/null", "/usr", "/x", "/y", "/keys/age.txt"} {
		assertContains(t, p.readOnly, want)
	}
	if !p.denyTCPConnect {
		t.Fatal("denyTCPConnect = false, want true")
	}
}

func assertContains(t *testing.T, values []string, want string) {
	t.Helper()
	for _, value := range values {
		if value == want {
			return
		}
	}
	t.Fatalf("%q not in %#v", want, values)
}
