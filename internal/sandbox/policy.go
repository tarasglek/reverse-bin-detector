package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// Policy is a filesystem/network allowlist, rendered as landrun flags by
// Command. landrun denies TCP bind/connect unless unrestrictedNetwork is set.
type Policy struct {
	readOnly            []string
	readOnlyExec        []string
	readWriteExec       []string // see WithWritable
	readWrite           []string
	unrestrictedNetwork bool
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
			p.readWrite = append(p.readWrite, data)
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
		p.readOnly = append(p.readOnly, etcSymlinkGrants(etcDir, appDir, granted)...)
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
	if p.unrestrictedNetwork {
		args = append(args, "--unrestricted-network")
	}
	return args
}
