//go:build linux

package sandbox

import (
	"fmt"
	"os"
	"slices"

	"github.com/landlock-lsm/go-landlock/landlock"
	ll "github.com/landlock-lsm/go-landlock/landlock/syscall"
)

type LandlockOptions struct {
	AllowUnsafeNoLandlock bool
}

func ApplyDetection(appDir string, env map[string]string, opts LandlockOptions) error {
	return Apply(DetectionPolicy(appDir, env), opts)
}

// Apply restricts the current process to p using go-landlock. Read-only and
// read-only-exec paths are equivalent here: landlock RO rules include execute.
func Apply(p Policy, opts LandlockOptions) error {
	if opts.AllowUnsafeNoLandlock {
		return nil
	}

	var rules []landlock.Rule
	for _, path := range slices.Concat(p.readOnly, p.readOnlyExec) {
		if rule, ok := pathRule(path, false); ok {
			rules = append(rules, rule)
		}
	}
	for _, path := range p.readWrite {
		if rule, ok := pathRule(path, true); ok {
			rules = append(rules, rule)
		}
	}
	if len(rules) > 0 {
		if err := landlock.V7.RestrictPaths(rules...); err != nil {
			return fmt.Errorf("apply landlock filesystem policy: %w", err)
		}
	}

	if p.denyTCPConnect {
		// Restrict only TCP connect. This denies outgoing TCP connections while
		// preserving bind/listen behavior needed for detector port allocation.
		if err := landlock.MustConfig(landlock.AccessNetSet(ll.AccessNetConnectTCP)).RestrictNet(); err != nil {
			return fmt.Errorf("apply landlock network policy: %w", err)
		}
	}
	return nil
}

func pathRule(path string, readWrite bool) (landlock.Rule, bool) {
	if path == "" {
		return nil, false
	}
	st, err := os.Stat(path)
	if err != nil {
		return nil, false
	}
	if readWrite {
		if st.IsDir() {
			return landlock.RWDirs(path), true
		}
		return landlock.RWFiles(path), true
	}
	if st.IsDir() {
		return landlock.RODirs(path), true
	}
	return landlock.ROFiles(path), true
}
