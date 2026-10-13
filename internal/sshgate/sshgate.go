// Package sshgate maps an SSH key to an app sandbox.
//
// sshd binds each key to an app with a per-key forced command in
// authorized_keys:
//
//	restrict,pty,command="/usr/lib/reverse-bin/rb-ssh APP" ssh-ed25519 AAAA...
//
// sshd runs forced commands as `$SHELL -c COMMAND`, and rb-ssh is also the
// service user's login shell, so rb-ssh sees either `rb-ssh APP` or
// `rb-ssh -c "<dir>/rb-ssh APP"`. Anything else, such as a key line without
// command=, su, or sudo -i, is refused instead of getting a general shell.
package sshgate

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Name is the argv[0] that selects SSH gate mode.
const Name = "rb-ssh"

// Config holds fixed host paths. They are compiled in, never read from the
// SSH session environment.
type Config struct {
	AppsRoot   string
	Path       string
	AgeKeyFile string
}

// Request is a validated SSH session: which app sandbox to enter and what to run there.
type Request struct {
	AppDir  string
	Command []string
}

var appName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// passthroughEnv are client terminal settings worth keeping inside the sandbox.
var passthroughEnv = []string{"TERM", "COLORTERM", "LANG", "LC_ALL"}

// IsInvocation reports whether argv[0] selects SSH gate mode. Login shells get a leading "-".
func IsInvocation(argv0 string) bool {
	return strings.TrimPrefix(filepath.Base(argv0), "-") == Name
}

// Run validates the session and hands it to asApp with a fixed PATH and age key.
func Run(ctx context.Context, argv []string, cfg Config, asApp func(ctx context.Context, appDir string, command []string) error) error {
	req, err := Parse(argv, os.LookupEnv, cfg.AppsRoot)
	if err != nil {
		return err
	}
	// Plan generation inherits this environment; sshd's must not choose binaries or keys.
	if err := os.Setenv("PATH", cfg.Path); err != nil {
		return err
	}
	if err := os.Setenv("SOPS_AGE_KEY_FILE", cfg.AgeKeyFile); err != nil {
		return err
	}
	if err := dieWithParent(); err != nil {
		return err
	}
	return asApp(ctx, req.AppDir, req.Command)
}

// Parse validates rb-ssh's arguments and builds the sandboxed command.
func Parse(argv []string, lookupEnv func(string) (string, bool), appsRoot string) (Request, error) {
	app, err := parseApp(argv)
	if err != nil {
		return Request{}, err
	}
	appDir, err := resolveAppDir(appsRoot, app)
	if err != nil {
		return Request{}, err
	}
	command, err := sessionCommand(lookupEnv)
	if err != nil {
		return Request{}, err
	}
	return Request{AppDir: appDir, Command: command}, nil
}

func parseApp(argv []string) (string, error) {
	usage := fmt.Errorf(`%s: use an SSH key whose authorized_keys line has command="/usr/lib/reverse-bin/%s APP"`, Name, Name)
	if len(argv) == 0 || strings.HasPrefix(filepath.Base(argv[0]), "-") {
		return "", usage
	}
	var app string
	switch args := argv[1:]; {
	case len(args) == 1:
		app = args[0]
	case len(args) == 2 && args[0] == "-c":
		fields := strings.Fields(args[1])
		if len(fields) != 2 || filepath.Base(fields[0]) != Name {
			return "", usage
		}
		app = fields[1]
	default:
		return "", usage
	}
	if !appName.MatchString(app) {
		return "", fmt.Errorf("%s: invalid app name %q", Name, app)
	}
	return app, nil
}

func resolveAppDir(appsRoot, app string) (string, error) {
	appDir := filepath.Join(appsRoot, app)
	root, err := filepath.EvalSymlinks(appsRoot)
	if err != nil {
		return "", fmt.Errorf("%s: apps root: %w", Name, err)
	}
	resolved, err := filepath.EvalSymlinks(appDir)
	if err != nil {
		return "", fmt.Errorf("%s: no such app %q", Name, app)
	}
	if rel, err := filepath.Rel(root, resolved); err != nil || rel == "." || strings.HasPrefix(rel, "..") {
		return "", fmt.Errorf("%s: app %q resolves outside %s", Name, app, appsRoot)
	}
	if st, err := os.Stat(resolved); err != nil || !st.IsDir() {
		return "", fmt.Errorf("%s: app %q is not a directory", Name, app)
	}
	return appDir, nil
}

func sessionCommand(lookupEnv func(string) (string, bool)) ([]string, error) {
	var command []string
	original, _ := lookupEnv("SSH_ORIGINAL_COMMAND")
	if original == "" {
		// Not a login shell: /etc/profile would replace the sandbox PATH.
		command = []string{"bash", "-i"}
	} else if fields := strings.Fields(original); len(fields) > 0 && isFileTransfer(filepath.Base(fields[0])) {
		return nil, fmt.Errorf("%s: sftp/scp is not supported; copy files with ssh and tar or cat", Name)
	} else {
		command = []string{"sh", "-c", original}
	}
	var env []string
	for _, key := range passthroughEnv {
		if value, ok := lookupEnv(key); ok && value != "" {
			env = append(env, key+"="+value)
		}
	}
	if len(env) == 0 {
		return command, nil
	}
	return append(append([]string{"env"}, env...), command...), nil
}

func isFileTransfer(program string) bool {
	switch program {
	case "sftp-server", "internal-sftp", "scp":
		return true
	}
	return false
}
