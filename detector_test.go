package main

import (
	"context"
	"encoding/json"
	"maps"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
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
		if before, ok := strings.CutSuffix(name, "*"); ok {
			name, mode = before, 0o755
		}
		writeFile(t, filepath.Join(dir, name), content, mode)
	}
	return dir
}

// setStaticRoot points staticRoot at a temp dir until the test ends.
func setStaticRoot(t *testing.T) {
	t.Helper()
	old := staticRoot
	staticRoot = t.TempDir()
	t.Cleanup(func() { staticRoot = old })
}

func planOf(t *testing.T, dir string) (App, error) {
	t.Helper()
	setStaticRoot(t)
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
		"explicit beats all":            {map[string]string{".env": "REVERSE_BIN_COMMAND=./run\n", "main.ts": ""}, []string{"sh", "-c", "./run"}},
		"deno beats static":             {map[string]string{"main.ts": "", "index.html": ""}, []string{"deno", "serve", "--watch", "--allow-all", "--host", "127.0.0.1", "--port", "", "main.ts"}},
		"main.py is not an entry point": {map[string]string{"main.py*": "", "index.html": ""}, []string{"reverse-bin-caddy", "file-server", "--listen", "", "--root", "."}},
		"dist":                          {map[string]string{"dist/index.html": ""}, []string{"reverse-bin-caddy", "file-server", "--listen", "", "--root", "dist"}},
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
// port in REVERSE_BIN_PORT unless the app sets it, a SOCKET_PATH app with its
// directory created and its stale socket removed inside the command, static
// apps on a managed socket.
func TestTransport(t *testing.T) {
	a, err := planOf(t, appDir(t, map[string]string{"main.ts": ""}))
	env := appEnv(a)
	if _, port, _ := net.SplitHostPort(a.ReverseProxyTo); err != nil || env["REVERSE_BIN_PORT"] != port || env["REVERSE_BIN_HOST"] != "127.0.0.1" || port == "" {
		t.Fatalf("default TCP: %q env %v err %v", a.ReverseProxyTo, env, err)
	}
	a, _ = planOf(t, appDir(t, map[string]string{"main.ts": "", ".env": "REVERSE_BIN_PORT=9001\nREVERSE_BIN_HOST=0.0.0.0\n"}))
	if a.ReverseProxyTo != "127.0.0.1:9001" || appEnv(a)["REVERSE_BIN_HOST"] != "0.0.0.0" {
		t.Fatalf("app's port/host: %q env %v; want 127.0.0.1:9001 (canonical) and the host kept", a.ReverseProxyTo, a.Envs)
	}
	dir := appDir(t, map[string]string{".env": "REVERSE_BIN_COMMAND=./srv\nSOCKET_PATH=data/run/s.sock\n"})
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
	setStaticRoot(t)
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

// contractJSON is a detector App with every field set, as json.Marshal writes
// it. caddy-reverse-bin's TestDetectorContract decodes this exact string; a
// field renamed on either side breaks one of the two tests.
const contractJSON = `{"executable":["unshare","--","sh","-c","./srv"],"working_directory":"/apps/a","envs":["HOME=/apps/a/data","REVERSE_BIN_PORT=9001"],"reverse_proxy_to":"127.0.0.1:9001","health_method":"GET","health_path":"/h","health_status":2}`

// TestContract pins the JSON the plugin decodes.
func TestContract(t *testing.T) {
	out, err := json.Marshal(App{Executable: []string{"unshare", "--", "sh", "-c", "./srv"}, WorkingDirectory: "/apps/a",
		Envs: []string{"HOME=/apps/a/data", "REVERSE_BIN_PORT=9001"}, ReverseProxyTo: "127.0.0.1:9001",
		HealthMethod: "GET", HealthPath: "/h", HealthStatus: 2})
	if err != nil || string(out) != contractJSON {
		t.Errorf("App marshals to\n%s\nwant\n%s", out, contractJSON)
	}
}

// TestPlanInvariants plans, sandboxed as in production, every combination of
// entry point and listener/health settings, and checks what must hold for any
// app: exactly the invalid combinations fail, including loader variables that
// would run code in unshare before the sandbox; the command starts with an
// absolute unshare --pid --kill-child, then an absolute landrun, then the sh
// PID 1, even when the app sets a hostile PATH; a static app gets no network;
// Caddy dials only loopback or a socket inside the app dir or the static root.
func TestPlanInvariants(t *testing.T) {
	if err := RequireLandlock(); err != nil {
		if os.Getenv("CI") != "" {
			t.Fatal(err) // these guards must run in CI
		}
		t.Skip(err)
	}
	entries := map[string]map[string]string{
		"explicit": {".env": "REVERSE_BIN_COMMAND=./srv\n"},
		"deno":     {"main.ts": ""},
		"static":   {"index.html": ""},
		"dist":     {"dist/index.html": ""},
		"none":     {},
	}
	settings := map[string]struct {
		env     string
		mustErr bool
	}{
		"defaults":            {"", false},
		"path hijack":         {"PATH=/nonexistent\n", false},
		"tcp":                 {"REVERSE_BIN_HOST=0.0.0.0\nREVERSE_BIN_PORT=9001\n", false},
		"tcp remote":          {"REVERSE_BIN_HOST=10.0.0.5\nREVERSE_BIN_PORT=9001\n", true},
		"socket":              {"SOCKET_PATH=data/s.sock\n", false},
		"socket escapes":      {"SOCKET_PATH=../s.sock\n", true},
		"socket absolute":     {"SOCKET_PATH=/tmp/s.sock\n", true},
		"socket and tcp":      {"SOCKET_PATH=data/s.sock\nREVERSE_BIN_PORT=9001\n", true},
		"socket brace":        {"SOCKET_PATH=data/{http.request.header.X}.sock\n", true},
		"unknown key":         {"REVERSE_BIN_PROT=9001\n", true},
		"loader preload":      {"LD_PRELOAD=/x.so\n", true},
		"loader library path": {"LD_LIBRARY_PATH=/x\n", true},
		"gconv":               {"GCONV_PATH=/x\n", true},
		"health":              {"REVERSE_BIN_HEALTH_METHOD=get\nREVERSE_BIN_HEALTH_PATH=/h\nREVERSE_BIN_HEALTH_STATUS=2xx\n", false},
		"health status bogus": {"REVERSE_BIN_HEALTH_STATUS=ok\n", true},
	}
	for en, files := range entries {
		for sn, s := range settings {
			t.Run(en+"/"+sn, func(t *testing.T) {
				static := en == "static" || en == "dist"
				wantErr := s.mustErr || en == "none" ||
					static && (sn == "tcp" || sn == "socket") || en == "deno" && sn == "socket"
				fs := maps.Clone(files)
				fs[".env"] += s.env
				dir := appDir(t, fs)
				setStaticRoot(t)
				a, err := plan(context.Background(), dir, "", true, nil, false)
				if (err != nil) != wantErr {
					t.Fatalf("err = %v, want error: %v", err, wantErr)
				}
				if err != nil {
					return
				}
				x := a.Executable
				dash := slices.Index(x, "--")
				if filepath.Base(x[0]) != "unshare" || !filepath.IsAbs(x[0]) || !slices.Contains(x[:dash], "--kill-child") || !slices.Contains(x[:dash], "--pid") ||
					filepath.Base(x[dash+1]) != "landrun" || !filepath.IsAbs(x[dash+1]) {
					t.Fatalf("not absolute unshare --pid --kill-child -- absolute landrun: %q", x)
				}
				inner := x[dash+1+slices.Index(x[dash+1:], "--")+1:]
				if !slices.Equal(inner[:4], []string{"/bin/sh", "-c", `"$@"; exit $?`, "sh"}) {
					t.Errorf("landrun does not run the sh PID 1 first: %q", inner)
				}
				if static && slices.Contains(x, "--unrestricted-network") {
					t.Error("static app has network access")
				}
				if path, ok := strings.CutPrefix(a.ReverseProxyTo, "unix/"); ok {
					in := func(root string) bool { r, err := filepath.Rel(root, path); return err == nil && filepath.IsLocal(r) }
					if !in(dir) && !in(staticRoot) {
						t.Errorf("socket %s outside the app dir and static root", path)
					}
				} else if host, _, err := net.SplitHostPort(a.ReverseProxyTo); err != nil || !net.ParseIP(host).IsLoopback() {
					t.Errorf("dials %q, want loopback", a.ReverseProxyTo)
				}
				if sn == "health" && (a.HealthMethod != "GET" || a.HealthPath != "/h" || a.HealthStatus != 2) {
					t.Errorf("health = %s %s %d, want GET /h 2", a.HealthMethod, a.HealthPath, a.HealthStatus)
				}
			})
		}
	}
}

// FuzzParseDotEnv feeds app-controlled .env bytes to the parser: it must not
// panic, and every key it returns is non-empty and trimmed, with no "=" and
// no key or value holding "\n", so one line cannot become a second KEY=value
// in the app's env. A "\r" may stay in a key: it cannot split an entry.
func FuzzParseDotEnv(f *testing.F) {
	for _, s := range []string{"A=1\n", "export B='x y'\n# c\n", "=v\nk\n", " K = \"v\" \r\n", "A=1\nA=2\n"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		env, err := parseDotEnv(b)
		if err != nil {
			return
		}
		for k, v := range env {
			if k == "" || k != strings.TrimSpace(k) || strings.ContainsAny(k, "=\n") || strings.Contains(v, "\n") {
				t.Fatalf("parsed %q to key %q value %q", b, k, v)
			}
		}
	})
}
