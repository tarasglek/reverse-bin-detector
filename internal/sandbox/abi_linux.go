//go:build linux

package sandbox

import "syscall"

// landlockABI returns the kernel's Landlock ABI version, or 0 without Landlock.
func landlockABI() int {
	// landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION); the
	// syscall number is 444 on every architecture.
	abi, _, errno := syscall.Syscall(444, 0, 0, 1)
	if errno != 0 {
		return 0
	}
	return int(abi)
}
