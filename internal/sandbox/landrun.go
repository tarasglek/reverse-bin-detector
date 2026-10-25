package sandbox

import "fmt"

// MinLandlockABI is the oldest kernel Landlock ABI the sandbox accepts. ABI 6
// (Linux 6.12, Debian trixie) covers every right the policies use, including
// abstract UNIX socket and signal scoping. Newer ABIs only add restrictions,
// which landrun --best-effort applies when the kernel has them.
const MinLandlockABI = 6

// RequireLandlock fails below MinLandlockABI. landrun --best-effort silently
// degrades to no sandbox at all on a kernel without Landlock, so every plan
// that runs landrun must be gated by this check.
func RequireLandlock() error {
	if abi := landlockABI(); abi < MinLandlockABI {
		return fmt.Errorf("kernel Landlock ABI %d < %d: refusing to run without a sandbox", abi, MinLandlockABI)
	}
	return nil
}

// Command wraps command in landrun restricted to p. Environment variables are
// passed by name: landrun copies their values from its own environment, so
// secrets never appear in argv, which every host user can read.
//
// landrun v0.1.17 fails with `Failed to find binary: exec: ""` when command[0]
// equals the name of a landrun flag in use (env, rox, ...); callers spell such
// commands with an absolute path, e.g. /usr/bin/env.
func Command(p Policy, envNames []string, command []string) []string {
	argv := append([]string{"landrun", "--best-effort"}, landrunArgs(p)...)
	for _, name := range envNames {
		argv = append(argv, "--env", name)
	}
	argv = append(argv, "--")
	return append(argv, command...)
}
