// Command reverse-bin-detector turns an app directory into the App that
// reverse_bin runs, and runs commands inside that app's sandbox.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

// Packaged paths. Tests override them with -ldflags -X; neither the app nor
// an SSH session can.
var (
	version       = "dev"
	commit        = "unknown"
	buildDate     = "unknown"
	staticRoot    = "/run/reverse-bin/static-apps"
	sshAppsRoot   = "/var/lib/reverse-bin/apps"
	sshPath       = "/usr/lib/reverse-bin:/usr/bin:/bin"
	sshAgeKeyFile = "/var/lib/reverse-bin/keys/age.key"
)

const usage = `usage: reverse-bin-detector [--public-host=HOST] APP_DIR
       reverse-bin-detector [--public-host=HOST] --as-app|--as-app-dev APP_DIR -- COMMAND [ARGS...]`

func main() {
	ctx := context.Background()
	var err error
	if IsInvocation(os.Args[0]) {
		cfg := Config{AppsRoot: sshAppsRoot, Path: sshPath, AgeKeyFile: sshAgeKeyFile}
		err = Run(ctx, os.Args, cfg, func(ctx context.Context, appDir string, command []string) error {
			return execAsApp(ctx, appDir, "", command, true)
		})
	} else {
		err = run(ctx, os.Args[1:], os.Stdout)
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		os.Exit(exitErr.ExitCode())
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("reverse-bin-detector", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	noSandbox := fs.Bool("no-runtime-sandbox", false, "tests only: plan without landrun")
	showVersion := fs.Bool("version", false, "print version")
	asApp := fs.Bool("as-app", false, "run COMMAND in the app's sandbox")
	asAppDev := fs.Bool("as-app-dev", false, "like --as-app, with the app source writable")
	publicHost := fs.String("public-host", "", "public host[:port] the app is served at over https")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("%w\n%s", err, usage)
	}
	if *showVersion {
		_, err := fmt.Fprintf(stdout, "%s %s %s\n", version, commit, buildDate)
		return err
	}
	rest := fs.Args()
	if *asApp || *asAppDev {
		if *asApp && *asAppDev || *noSandbox || len(rest) < 3 || rest[1] != "--" {
			return errors.New(usage)
		}
		return execAsApp(ctx, rest[0], *publicHost, rest[2:], *asAppDev)
	}
	if len(rest) != 1 {
		return errors.New(usage)
	}
	appDir, err := filepath.Abs(rest[0])
	if err != nil {
		return err
	}
	a, err := plan(ctx, appDir, *publicHost, !*noSandbox, nil, false)
	if err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(a)
}

// execAsApp replaces the detector with command inside the app's sandbox,
// environment and working directory, so signals and hangups reach the
// sandbox directly.
func execAsApp(ctx context.Context, appDir, publicHost string, command []string, writable bool) error {
	appDir, err := filepath.Abs(appDir)
	if err != nil {
		return err
	}
	a, err := plan(ctx, appDir, publicHost, true, command, writable)
	if err != nil {
		return err
	}
	path, err := exec.LookPath(a.Executable[0])
	if err != nil {
		return err
	}
	if err := os.Chdir(a.WorkingDirectory); err != nil {
		return err
	}
	return syscall.Exec(path, a.Executable, a.Envs)
}
