package sandbox

import "testing"

func TestApplyAllowsUnsafeNoLandlock(t *testing.T) {
	if err := Apply(DetectionPolicy(t.TempDir(), nil), LandlockOptions{AllowUnsafeNoLandlock: true}); err != nil {
		t.Fatalf("Apply unsafe: %v", err)
	}
}
