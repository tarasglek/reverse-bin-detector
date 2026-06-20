package sandbox

import (
	"path/filepath"
	"strings"
)

type Policy struct {
	ReadOnly       []string
	ReadWrite      []string
	DenyTCPConnect bool
}

func DetectionPolicy(appDir string, env map[string]string) Policy {
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
	return Policy{ReadOnly: ro, DenyTCPConnect: true}
}
