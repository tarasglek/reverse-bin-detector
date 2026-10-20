package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"

	"github.com/tarasglek/reverse-bin-detector/internal/detector"
	"github.com/tarasglek/reverse-bin-detector/internal/sshgate"
)

// Packaged rb-ssh paths. Tests override them with -ldflags -X; the SSH
// session environment never does.
var (
	sshAppsRoot   = "/var/lib/reverse-bin/apps"
	sshPath       = "/usr/lib/reverse-bin:/usr/bin:/bin"
	sshAgeKeyFile = "/var/lib/reverse-bin/keys/age.key"
)

func main() {
	ctx := context.Background()
	var err error
	if sshgate.IsInvocation(os.Args[0]) {
		cfg := sshgate.Config{AppsRoot: sshAppsRoot, Path: sshPath, AgeKeyFile: sshAgeKeyFile}
		err = sshgate.Run(ctx, os.Args, cfg, detector.RunAsAppDev)
	} else {
		err = detector.Run(ctx, os.Args[1:], os.Stdout)
	}
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
