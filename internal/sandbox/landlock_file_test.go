//go:build linux

package sandbox

import (
	"os"
	"path/filepath"
	"testing"
)

func TestApplyDetectionPolicyAllowsRegularSOPSKeyRule(t *testing.T) {
	appDir := t.TempDir()
	key := filepath.Join(t.TempDir(), "age.key")
	if err := os.WriteFile(key, []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ApplyDetection(appDir, map[string]string{"SOPS_AGE_KEY_FILE": key}, LandlockOptions{AllowUnsafeNoLandlock: true}); err != nil {
		t.Fatalf("Apply unsafe with regular key file: %v", err)
	}
	if _, ok := pathRule(key, false); !ok {
		t.Fatalf("pathRule(%q) not ok", key)
	}
}
