package sandbox

import (
	"os"
	"path/filepath"
	"strings"
)

// Policy is the filesystem/network allowlist shared by the detection sandbox
// (rendered by Apply via go-landlock) and the app runtime sandbox (rendered by
// LandrunArgs). Both sandboxes derive from the same constructors so that grants
// cannot drift between the two code paths.
type Policy struct {
	readOnly            []string
	readOnlyExec        []string
	readWrite           []string
	denyTCPConnect      bool // Apply only; landrun denies connect by default.
	unrestrictedNetwork bool // LandrunArgs only.
}

// etcSymlinks lists /etc entries that are commonly symlinks into directories
// outside the base allowlist (systemd-resolved manages resolv.conf under /run).
var etcSymlinks = []string{"resolv.conf"}

// broadDirs are never granted as symlink-target parents, no matter where a
// symlink in /etc points.
var broadDirs = []string{"/", "/run", "/var", "/tmp", "/home", "/root"}

// DetectionPolicy restricts the plan-emitting detector child.
func DetectionPolicy(appDir string, env map[string]string) Policy {
	return detectionPolicy(appDir, env, "/etc")
}

func detectionPolicy(appDir string, env map[string]string, etcDir string) Policy {
	ro := []string{appDir, "/dev/null", "/bin", "/usr", "/lib", "/lib64", "/etc"}
	if pathEnv := env["PATH"]; pathEnv != "" {
		for _, path := range strings.Split(pathEnv, string(filepath.ListSeparator)) {
			if path != "" {
				ro = append(ro, path)
			}
		}
	}
	if key := env["SOPS_AGE_KEY_FILE"]; key != "" {
		ro = append(ro, key)
	}
	ro = append(ro, etcSymlinkGrants(etcDir, appDir, ro)...)
	return Policy{readOnly: ro, denyTCPConnect: true}
}

// RuntimePolicy restricts the app process launched through landrun. Static
// apps only serve files and get no network, sysfs, data dir, or DNS grants.
func RuntimePolicy(appDir string, static bool, socketDir string) Policy {
	return runtimePolicy(appDir, static, socketDir, "/etc")
}

func runtimePolicy(appDir string, static bool, socketDir string, etcDir string) Policy {
	p := Policy{
		readOnlyExec: []string{"/bin", "/usr", "/lib", "/lib64", "/proc", "/sys/fs/cgroup"},
		readOnly:     []string{"/etc"},
		readWrite:    []string{"/dev"},
	}
	if st, err := os.Stat(filepath.Join(appDir, "data")); !static && err == nil && st.IsDir() {
		p.readWrite = append(p.readWrite, filepath.Join(appDir, "data"))
	}
	if socketDir != "" {
		p.readWrite = append(p.readWrite, socketDir)
	}
	p.readOnlyExec = append(p.readOnlyExec, appDir)
	if !static {
		p.readOnly = append(p.readOnly, "/sys")
		p.unrestrictedNetwork = true
		granted := append(append([]string(nil), p.readOnly...), p.readOnlyExec...)
		p.readOnly = append(p.readOnly, etcSymlinkGrants(etcDir, appDir, granted)...)
	}
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
		if underAny(appDir, []string{parent}) || isOneOf(parent, broadDirs) {
			continue
		}
		grants = append(grants, parent)
	}
	return grants
}

func isOneOf(dir string, dirs []string) bool {
	for _, d := range dirs {
		if dir == d {
			return true
		}
	}
	return false
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

// LandrunArgs renders p as landrun flags (without the command or --env).
func LandrunArgs(p Policy) []string {
	var args []string
	for _, path := range p.readOnlyExec {
		args = append(args, "--rox", path)
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
