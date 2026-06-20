//go:build !linux

package sandbox

import "fmt"

type LandlockOptions struct {
	AllowUnsafeNoLandlock bool
}

func Apply(policy Policy, opts LandlockOptions) error {
	_ = policy
	if opts.AllowUnsafeNoLandlock {
		return nil
	}
	return fmt.Errorf("landlock is unavailable on this platform")
}
