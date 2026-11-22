package main

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func writeFile(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}

// appDir makes an app directory holding files (name -> content; a name
// ending in "*" is executable, the star dropped).
func appDir(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		mode := os.FileMode(0o644)
		if strings.HasSuffix(name, "*") {
			name, mode = strings.TrimSuffix(name, "*"), 0o755
		}
		writeFile(t, filepath.Join(dir, name), content, mode)
	}
	return dir
}

func planOf(t *testing.T, dir string) (App, error) {
	t.Helper()
	staticRoot = t.TempDir()
	return plan(context.Background(), dir, "", false, nil, false)
}

// appEnv turns an App's KEY=value list into a map.
func appEnv(a App) map[string]string {
	env := map[string]string{}
	for _, kv := range a.Envs {
		k, v, _ := strings.Cut(kv, "=")
		env[k] = v
	}
	return env
}

// TestKinds pins which entry point wins and the command each kind runs.
func TestKinds(t *testing.T) {
	for name, tc := range map[string]struct {
		files map[string]string
		want  []string // "" entries are not compared (ports, socket paths)
	}{
		"explicit beats all":               {map[string]string{".env": "REVERSE_BIN_COMMAND=./run\n", "main.ts": ""}, []string{"sh", "-c", "./run"}},
		"deno":                             {map[string]string{"main.ts": "", "main.py*": ""}, []string{"deno", "serve", "--watch", "--allow-all", "--host", "127.0.0.1", "--port", "", "main.ts"}},
		"python":                           {map[string]string{"main.py*": "", "index.html": ""}, []string{"sh", "-c", `rm -f -- "$SOCKET_PATH" && exec "$@"`, "sh", "./main.py"}},
		"main.py not executable is static": {map[string]string{"main.py": "", "index.html": ""}, []string{"reverse-bin-caddy", "file-server", "--listen", "", "--root", "."}},
		"dist":                             {map[string]string{"dist/index.html": ""}, []string{"reverse-bin-caddy", "file-server", "--listen", "", "--root", "dist"}},
	} {
		a, err := planOf(t, appDir(t, tc.files))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got := append([]string(nil), a.Executable...)
		for i, w := range tc.want {
			if w == "" && i < len(got) {
				got[i] = ""
			}
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: executable = %q, want %q", name, a.Executable, tc.want)
		}
	}
	if _, err := planOf(t, t.TempDir()); err == nil || !strings.Contains(err.Error(), "no entry point") {
		t.Errorf("empty dir: err = %v, want no entry point", err)
	}
}

// TestTransport pins the address handling, as in v0.1.22: TCP with a free
// port in REVERSE_BIN_PORT unless the app sets it, a python app without
// listener config on data/reverse-bin.sock, a SOCKET_PATH app with its
// directory created and its stale socket removed inside the command, static
// apps on a managed socket.
func TestTransport(t *testing.T) {
	a, err := planOf(t, appDir(t, map[string]string{"main.ts": ""}))
	env := appEnv(a)
	if _, port, _ := net.SplitHostPort(a.ReverseProxyTo); err != nil || env["REVERSE_BIN_PORT"] != port || env["REVERSE_BIN_HOST"] != "127.0.0.1" || port == "" {
		t.Fatalf("default TCP: %q env %v err %v", a.ReverseProxyTo, env, err)
	}
	a, _ = planOf(t, appDir(t, map[string]string{"main.py*": "", ".env": "REVERSE_BIN_PORT=9001\nREVERSE_BIN_HOST=0.0.0.0\n"}))
	if a.ReverseProxyTo != "127.0.0.1:9001" || appEnv(a)["REVERSE_BIN_HOST"] != "0.0.0.0" {
		t.Fatalf("app's port/host: %q env %v; want 127.0.0.1:9001 (canonical) and the host kept", a.ReverseProxyTo, a.Envs)
	}
	dir := appDir(t, map[string]string{"main.py*": ""})
	if a, _ = planOf(t, dir); a.ReverseProxyTo != "unix/"+filepath.Join(dir, "data/reverse-bin.sock") || appEnv(a)["SOCKET_PATH"] != "data/reverse-bin.sock" {
		t.Fatalf("python default: %q env %v", a.ReverseProxyTo, a.Envs)
	}
	dir = appDir(t, map[string]string{".env": "REVERSE_BIN_COMMAND=./srv\nSOCKET_PATH=data/run/s.sock\n"})
	a, err = planOf(t, dir)
	want := []string{"sh", "-c", `rm -f -- "$SOCKET_PATH" && exec "$@"`, "sh", "sh", "-c", "./srv"}
	if err != nil || a.ReverseProxyTo != "unix/"+filepath.Join(dir, "data/run/s.sock") || !reflect.DeepEqual(a.Executable, want) {
		t.Fatalf("SOCKET_PATH: %q executable %q err %v", a.ReverseProxyTo, a.Executable, err)
	}
	if st, err := os.Stat(filepath.Join(dir, "data/run")); err != nil || !st.IsDir() {
		t.Fatalf("socket directory not created: %v", err)
	}
	a, err = planOf(t, appDir(t, map[string]string{"index.html": ""}))
	if err != nil || !strings.HasPrefix(a.ReverseProxyTo, "unix/"+staticRoot+"/app-") || !strings.HasSuffix(a.ReverseProxyTo, "/reverse-bin.sock") || a.Executable[3] != "unix/"+a.ReverseProxyTo[5:] {
		t.Fatalf("static: %q executable %q err %v", a.ReverseProxyTo, a.Executable, err)
	}
	for name, env := range map[string]string{
		"socket outside app": "REVERSE_BIN_COMMAND=x\nSOCKET_PATH=../s.sock\n",
		"socket and TCP":     "REVERSE_BIN_COMMAND=x\nSOCKET_PATH=s.sock\nREVERSE_BIN_PORT=1\n",
		"deno on a socket":   "SOCKET_PATH=s.sock\n",
		"static on a socket": "SOCKET_PATH=s.sock\n",
		"unknown key":        "REVERSE_BIN_COMMAND=x\nREVERSE_BIN_PROT=1\n",
		"bad status":         "REVERSE_BIN_COMMAND=x\nREVERSE_BIN_HEALTH_STATUS=ok\n",
		"bad public host":    "REVERSE_BIN_COMMAND=x\nREVERSE_BIN_PUBLIC_HOST=a/b\n",
	} {
		files := map[string]string{".env": env}
		switch name {
		case "deno on a socket":
			files["main.ts"] = ""
		case "static on a socket":
			files["index.html"] = ""
		}
		if _, err := planOf(t, appDir(t, files)); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}

// TestEnvAndHealth pins what the app gets: its env file, defaults it did not
// set, the public host (the app's own wins), and the health fields: path "/"
// by default, empty REVERSE_BIN_HEALTH_PATH for connect-only.
func TestEnvAndHealth(t *testing.T) {
	dir := appDir(t, map[string]string{"main.ts": "", ".env": "A='x y'\n# c\nHOME=/h\nREVERSE_BIN_HEALTH_METHOD=get\nREVERSE_BIN_HEALTH_STATUS=2xx\n"})
	staticRoot = t.TempDir()
	a, err := plan(context.Background(), dir, "Demo.Example.test", false, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]string{"A": "x y", "HOME": "/h", "TMPDIR": "data", "REVERSE_BIN_PUBLIC_HOST": "demo.example.test"} {
		if got := appEnv(a)[k]; got != want {
			t.Errorf("env %s = %q, want %q", k, got, want)
		}
	}
	if a.HealthPath != "/" || a.HealthMethod != "GET" || a.HealthStatus != 2 {
		t.Errorf("health %q %q %d, want / GET 2", a.HealthPath, a.HealthMethod, a.HealthStatus)
	}
	writeFile(t, filepath.Join(dir, ".env"), "REVERSE_BIN_HEALTH_PATH=\nREVERSE_BIN_PUBLIC_HOST=own.test\n", 0o644)
	a, _ = plan(context.Background(), dir, "flag.test", false, nil, false)
	if env := appEnv(a); a.HealthPath != "" || env["REVERSE_BIN_PUBLIC_HOST"] != "own.test" || env["HOME"] != filepath.Join(dir, "data") {
		t.Errorf("empty health path / own public host / default HOME: %q %v", a.HealthPath, a.Envs)
	}
}

// TestLoadEnv pins the env sources: sops gets ciphertext on stdin, a
// leading "export " is ignored, an over-long line is an error rather than a
// silently truncated env, both sources at once is an error, and a symlink to
// another app's files is an error rather than a read or a "missing".
func TestLoadEnv(t *testing.T) {
	bin := t.TempDir()
	writeFile(t, filepath.Join(bin, "sops"), "#!/bin/sh\n[ \"$*\" = 'decrypt --input-type json --output-type dotenv' ] || exit 9\nread -r l\n[ \"$l\" = '{\"sops\":1}' ] || exit 8\necho SECRET=from-sops\n", 0o755)
	t.Setenv("PATH", bin)
	env, err := loadEnv(context.Background(), appDir(t, map[string]string{"secrets.enc.json": `{"sops":1}` + "\n"}), false)
	if err != nil || env["SECRET"] != "from-sops" {
		t.Fatalf("sops: %v %v", env, err)
	}
	env, err = loadEnv(context.Background(), appDir(t, map[string]string{".env": "export A=1\n  export B = 2\n"}), false)
	if err != nil || env["A"] != "1" || env["B"] != "2" {
		t.Fatalf("export prefix: %v %v", env, err)
	}
	if env, err := loadEnv(context.Background(), appDir(t, map[string]string{".env": "A=" + strings.Repeat("x", 70<<10) + "\nB=1\n"}), false); err == nil {
		t.Fatalf("over-long line: loaded %d keys, want an error", len(env))
	}
	if _, err := loadEnv(context.Background(), appDir(t, map[string]string{".env": "", "secrets.enc.json": "{}"}), false); err == nil || !strings.Contains(err.Error(), "not both") {
		t.Fatalf("two sources: %v", err)
	}
	other := appDir(t, map[string]string{"victim": "SECRET=other\n"})
	for _, name := range []string{".env", "secrets.enc.json"} {
		dir := t.TempDir()
		if err := os.Symlink(filepath.Join(other, "victim"), filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
		if env, err := loadEnv(context.Background(), dir, false); err == nil {
			t.Fatalf("%s symlink: loaded %v, want error", name, env)
		}
	}
}

// TestSOPSUnderLandrun runs the production path: sops confined by landrun,
// ciphertext on stdin, the age key readable by name, nothing else writable.
func TestSOPSUnderLandrun(t *testing.T) {
	landrun := requireLandrun(t)
	bin, escape, key := t.TempDir(), filepath.Join(t.TempDir(), "escape"), filepath.Join(t.TempDir(), "age.key")
	writeFile(t, key, "AGE-SECRET-KEY-TEST\n", 0o600)
	writeFile(t, filepath.Join(bin, "sops"), "#!/bin/sh\nread -r l\ntouch "+escape+" || true\necho \"KEY=$(cat \"$SOPS_AGE_KEY_FILE\")\"\necho \"IN=$l\"\n", 0o755)
	t.Setenv("PATH", bin+":"+filepath.Dir(landrun)+":/usr/bin:/bin")
	t.Setenv("SOPS_AGE_KEY_FILE", key)
	env, err := loadEnv(context.Background(), appDir(t, map[string]string{"secrets.enc.json": `{"sops":1}` + "\n"}), true)
	if err != nil || env["KEY"] != "AGE-SECRET-KEY-TEST" || env["IN"] != `{"sops":1}` {
		t.Fatalf("env %v err %v", env, err)
	}
	if _, err := os.Stat(escape); err == nil {
		t.Fatal("sops wrote outside its sandbox")
	}
}

func requireLandrun(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("landrun")
	if err != nil {
		t.Skip("landrun not installed")
	}
	if err := RequireLandlock(); err != nil {
		t.Skip(err)
	}
	return path
}
