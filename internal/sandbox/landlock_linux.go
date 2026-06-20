//go:build linux

package sandbox

import (
	"fmt"
	"os"

	"github.com/landlock-lsm/go-landlock/landlock"
	ll "github.com/landlock-lsm/go-landlock/landlock/syscall"
)

type LandlockOptions struct {
	AllowUnsafeNoLandlock bool
}

func Apply(policy Policy, opts LandlockOptions) error {
	if opts.AllowUnsafeNoLandlock {
		return nil
	}

	var rules []landlock.Rule
	for _, path := range existingPaths(policy.ReadOnly) {
		rules = append(rules, landlock.RODirs(path))
	}
	for _, path := range existingPaths(policy.ReadWrite) {
		rules = append(rules, landlock.RWDirs(path))
	}
	if len(rules) > 0 {
		if err := landlock.V7.RestrictPaths(rules...); err != nil {
			return fmt.Errorf("apply landlock filesystem policy: %w", err)
		}
	}

	if policy.DenyTCPConnect {
		// Restrict only TCP connect. This denies outgoing TCP connections while
		// preserving bind/listen behavior needed for detector port allocation.
		if err := landlock.MustConfig(landlock.AccessNetSet(ll.AccessNetConnectTCP)).RestrictNet(); err != nil {
			return fmt.Errorf("apply landlock network policy: %w", err)
		}
	}
	return nil
}

func existingPaths(paths []string) []string {
	out := make([]string, 0, len(paths))
	for _, path := range paths {
		if path == "" {
			continue
		}
		if _, err := os.Stat(path); err == nil {
			out = append(out, path)
		}
	}
	return out
}
