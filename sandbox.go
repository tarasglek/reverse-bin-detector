package main

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// Policy is a filesystem/network allowlist, rendered as landrun flags by
// Command. landrun denies TCP bind/connect unless unrestrictedNetwork is set;
// with it, a non-empty bindTCP still limits binding to those ports.
type Policy struct {
	readOnly            []string
	readOnlyExec        []string
	readWriteExec       []string // app data/ and WithWritable
	readWrite           []string
	unix                []string // pathname unix sockets it may connect to (ABI 9)
	unrestrictedNetwork bool
	bindTCP             []string // ports or ranges; "0": ports the kernel picks
}

// etcSymlinks lists /etc entries that are commonly symlinks into directories
// outside the base allowlist (systemd-resolved manages resolv.conf under /run).
var etcSymlinks = []string{"resolv.conf"}

// broadDirs are never granted as symlink-target parents, no matter where a
// symlink in /etc points. Exact match only: depth-2 parents such as
// /run/resolvconf and /run/NetworkManager are legitimate resolv.conf homes.
var broadDirs = []string{"/", "/run", "/var", "/tmp", "/home", "/root"}

// SOPSPolicy restricts sops decrypting an app's secrets: system files, the
// sops binary, and the age key, with no network. Secrets files are tenant
// controlled, and their metadata can point sops at KMS, Vault, cloud metadata
// endpoints, or gpg.
func SOPSPolicy(sopsPath, ageKeyFile string) Policy {
	p := Policy{
		readOnlyExec: []string{"/bin", "/usr", "/lib", "/lib64", sopsPath},
		readOnly:     []string{"/etc"},
	}
	if ageKeyFile != "" {
		p.readOnly = append(p.readOnly, ageKeyFile)
	}
	return p
}

// RuntimePolicy restricts the app process launched through landrun. Static
// apps only serve files and get no network, sysfs, data dir, or DNS grants.
func RuntimePolicy(appDir string, static bool, socketDir string) (Policy, error) {
	return runtimePolicy(appDir, static, socketDir, "/etc")
}

func runtimePolicy(appDir string, static bool, socketDir string, etcDir string) (Policy, error) {
	p := Policy{
		readOnlyExec: []string{"/bin", "/usr", "/lib", "/lib64", "/proc", "/sys/fs/cgroup"},
		readOnly:     []string{"/etc"},
		readWrite:    []string{"/dev"},
	}
	// Lstat: landrun follows symlinks, so a tenant's data -> ../other/data
	// would grant write access to another app.
	data := filepath.Join(appDir, "data")
	if st, err := os.Lstat(data); !static && err == nil {
		if st.Mode()&os.ModeSymlink != 0 {
			return Policy{}, fmt.Errorf("%s must be a directory, not a symlink", data)
		}
		if st.IsDir() {
			// rwx, not rw: apps run tools they install in data/, and that must
			// not depend on the --rox app dir grant above it.
			p.readWriteExec = append(p.readWriteExec, data)
		}
	}
	if socketDir != "" {
		p.readWrite = append(p.readWrite, socketDir)
	}
	p.readOnlyExec = append(p.readOnlyExec, appDir)
	if !static {
		p.readOnly = append(p.readOnly, "/sys")
		p.unrestrictedNetwork = true
		granted := slices.Concat(p.readOnly, p.readOnlyExec)
		resolver := etcSymlinkGrants(etcDir, appDir, granted)
		p.readOnly = append(p.readOnly, resolver...)
		// Its own sockets, and the resolver's (systemd-resolved's varlink).
		p.unix = append([]string{appDir}, resolver...)
	}
	return p, nil
}

// WithWritable moves dir from read/execute to read/write/execute. It is the
// only difference between a production app sandbox and a dev session.
func (p Policy) WithWritable(dir string) Policy {
	p.readOnlyExec = slices.DeleteFunc(slices.Clone(p.readOnlyExec), func(s string) bool { return s == dir })
	p.readWriteExec = append(slices.Clone(p.readWriteExec), dir)
	return p
}

// etcSymlinkGrants returns the parent directories of well-known /etc symlink
// targets that lie outside granted. The parent (not the file) is granted
// because Landlock rules pin inodes and systemd-resolved replaces its files
// atomically. Missing or broken links are skipped; broad parents are refused.
func etcSymlinkGrants(etcDir, appDir string, granted []string) []string {
	var grants []string
	for _, name := range etcSymlinks {
		link := filepath.Join(etcDir, name)
		if st, err := os.Lstat(link); err != nil || st.Mode()&os.ModeSymlink == 0 {
			continue
		}
		target, err := filepath.EvalSymlinks(link)
		if err != nil {
			continue
		}
		parent := filepath.Dir(target)
		if underAny(parent, granted) {
			continue
		}
		// Refuse parents that would expose the app tree or a broad system dir.
		if underAny(appDir, []string{parent}) || slices.Contains(broadDirs, parent) {
			continue
		}
		grants = append(grants, parent)
	}
	return grants
}

// underAny reports whether path equals or is inside one of dirs.
func underAny(path string, dirs []string) bool {
	for _, dir := range dirs {
		if dir == "" {
			continue
		}
		if path == dir || strings.HasPrefix(path, strings.TrimSuffix(dir, "/")+"/") {
			return true
		}
	}
	return false
}

func landrunArgs(p Policy) []string {
	var args []string
	for _, path := range p.readOnlyExec {
		args = append(args, "--rox", path)
	}
	for _, path := range p.readWriteExec {
		args = append(args, "--rwx", path)
	}
	for _, path := range p.readOnly {
		args = append(args, "--ro", path)
	}
	for _, path := range p.readWrite {
		args = append(args, "--rw", path)
	}
	for _, path := range p.unix {
		args = append(args, "--unix", path)
	}
	if p.unrestrictedNetwork {
		args = append(args, "--unrestricted-network")
	}
	for _, port := range p.bindTCP {
		args = append(args, "--bind-tcp", port)
	}
	return args
}

// MinLandlockABI is the oldest kernel Landlock ABI the sandbox accepts. ABI 6
// (Linux 6.12, Debian trixie) covers every right the policies use, including
// abstract UNIX socket and signal scoping. landrun applies the newer ABIs'
// default restrictions when the kernel has them, and warns on stderr when not.
const MinLandlockABI = 6

// UnixABI is the Landlock ABI that restricts pathname unix socket connects.
// landrun's strict mode refuses --unix below it, so it is passed only from it.
const UnixABI = 9

// RequireLandlock fails below MinLandlockABI, so every plan that runs landrun
// has every right its policy uses.
func RequireLandlock() error {
	if abi := landlockABI(); abi < MinLandlockABI {
		return fmt.Errorf("kernel Landlock ABI %d < %d: refusing to run without a sandbox", abi, MinLandlockABI)
	}
	return nil
}

// Command wraps command in landrun restricted to p. Environment variables are
// passed by name: landrun copies their values from its own environment, so
// secrets never appear in argv, which every host user can read. No
// --best-effort: an option the kernel cannot enforce is an error, not a
// silently weaker sandbox.
func Command(p Policy, envNames []string, command []string) []string {
	return commandFor(landlockABI(), p, envNames, command)
}

// commandFor is Command on a kernel with Landlock ABI abi.
func commandFor(abi int, p Policy, envNames []string, command []string) []string {
	if abi < UnixABI {
		p.unix = nil
	}
	argv := append([]string{"landrun"}, landrunArgs(p)...)
	for _, name := range envNames {
		argv = append(argv, "--env", name)
	}
	argv = append(argv, "--")
	return append(argv, command...)
}
