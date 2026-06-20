package sandbox

import "path/filepath"

// Policy is a small, portable vocabulary for filesystem/network sandboxing.
// Future runtime backends can map this to NetBSD pledge/unveil, Linux
// Landlock, Deno permissions, or similar mechanisms.
type Policy struct {
	ReadOnly       []string
	ReadWrite      []string
	AllowTCPBind   bool
	DenyTCPConnect bool
}

type Transport struct {
	Kind string
}

func SystemReadOnlyPaths() []string {
	return []string{"/bin", "/usr", "/lib", "/lib64", "/etc"}
}

func AppReadOnlyPath(appDir string) string { return appDir }

func AppDataReadWritePath(appDir string) string { return filepath.Join(appDir, "data") }

func SOPSReadOnlyPaths(env map[string]string) []string {
	if path := env["SOPS_AGE_KEY_FILE"]; path != "" {
		return []string{path}
	}
	return nil
}

func DetectionPolicy(appDir string, env map[string]string) Policy {
	ro := append([]string{AppReadOnlyPath(appDir)}, SystemReadOnlyPaths()...)
	ro = append(ro, SOPSReadOnlyPaths(env)...)
	return Policy{
		ReadOnly:       ro,
		AllowTCPBind:   true,
		DenyTCPConnect: true,
	}
}

func PythonRuntimePolicy(appDir string, transport Transport) Policy {
	return Policy{
		ReadOnly:       append([]string{AppReadOnlyPath(appDir)}, SystemReadOnlyPaths()...),
		ReadWrite:      []string{AppDataReadWritePath(appDir)},
		AllowTCPBind:   transport.Kind == "tcp",
		DenyTCPConnect: true,
	}
}

func DenoRuntimePolicy(appDir, denoPath, denoCache string, transport Transport) Policy {
	ro := append([]string{AppReadOnlyPath(appDir)}, SystemReadOnlyPaths()...)
	if denoPath != "" {
		ro = append(ro, denoPath)
	}
	if denoCache != "" {
		ro = append(ro, denoCache)
	}
	return Policy{
		ReadOnly:       ro,
		ReadWrite:      []string{AppDataReadWritePath(appDir)},
		AllowTCPBind:   transport.Kind == "tcp",
		DenyTCPConnect: false, // Smallweb-compatible permissive Deno networking for now.
	}
}

func StaticPolicy(appRoot string) Policy {
	return Policy{ReadOnly: []string{appRoot}}
}

func DenoServeArgs(host, port, entrypoint string) []string {
	return []string{"deno", "serve", "--watch", "--allow-all", "--host", host, "--port", port, entrypoint}
}
