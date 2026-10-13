package sshgate

import (
	"fmt"
	"os"
	"runtime"
	"syscall"
)

// dieWithParent makes the kernel SIGKILL this process, and so the exec'd
// unshare and its sandbox, when sshd's session process exits. Without a PTY,
// sshd sends no hangup when the client disconnects.
//
// The setting belongs to the calling thread and survives exec only when that
// same thread execs, so the goroutine stays locked to it.
func dieWithParent() error {
	runtime.LockOSThread()
	parent := os.Getppid()
	if _, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, syscall.PR_SET_PDEATHSIG, uintptr(syscall.SIGKILL), 0); errno != 0 {
		return fmt.Errorf("%s: set parent death signal: %w", Name, errno)
	}
	// A parent that exited before prctl never triggers the signal; we would
	// already have been reparented.
	if os.Getppid() != parent {
		return fmt.Errorf("%s: session parent already exited", Name)
	}
	return nil
}
