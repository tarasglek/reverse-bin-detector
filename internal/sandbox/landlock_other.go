//go:build !linux

package sandbox

import "fmt"

type LandlockOptions struct {
	AllowUnsafeNoLandlock bool
}

func ApplyDetection(appDir string, env map[string]string, opts LandlockOptions) error {
	if opts.AllowUnsafeNoLandlock {
		return nil
	}
	return fmt.Errorf("landlock is only supported on linux")
}
