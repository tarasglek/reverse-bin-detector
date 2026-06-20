package sandbox

import (
	"path/filepath"
	"strings"
)

type policy struct {
	readOnly       []string
	readWrite      []string
	denyTCPConnect bool
}

func detectionPolicy(appDir string, env map[string]string) policy {
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
	return policy{readOnly: ro, denyTCPConnect: true}
}
