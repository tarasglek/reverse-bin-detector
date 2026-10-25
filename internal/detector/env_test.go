package detector

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/tarasglek/reverse-bin-detector/internal/sandbox"
)

func TestLoadAppEnvLoadsDotEnv(t *testing.T) {
	appDir := t.TempDir()
	writeFile(t, filepath.Join(appDir, ".env"), "CUSTOM=1\nQUOTED='hello world'\nREVERSE_BIN_PORT=\n")
	env, err := LoadAppEnv(context.Background(), appDir, false)
	if err != nil {
		t.Fatalf("LoadAppEnv: %v", err)
	}
	for key, want := range map[string]string{"CUSTOM": "1", "QUOTED": "hello world", "REVERSE_BIN_PORT": ""} {
		if got := env[key]; got != want {
			t.Fatalf("env[%s] = %q, want %q", key, got, want)
		}
	}
}

func TestLoadAppEnvDecryptsSecretsEncJSONWithSOPS(t *testing.T) {
	appDir := t.TempDir()
	binDir := t.TempDir()
	writeFile(t, filepath.Join(appDir, "secrets.enc.json"), `{"sops":"metadata"}`+"\n")
	fakeSOPS := filepath.Join(binDir, "sops")
	// sops gets the ciphertext on stdin and no path it could follow.
	writeFile(t, fakeSOPS, "#!/bin/sh\n[ \"$*\" = 'decrypt --input-type json --output-type dotenv' ] || exit 9\nread -r line\n[ \"$line\" = '{\"sops\":\"metadata\"}' ] || exit 8\necho 'SECRET=from-sops'\necho 'EMPTY='\n")
	if err := os.Chmod(fakeSOPS, 0o755); err != nil {
		t.Fatalf("chmod fake sops: %v", err)
	}
	t.Setenv("PATH", binDir)
	env, err := LoadAppEnv(context.Background(), appDir, false)
	if err != nil {
		t.Fatalf("LoadAppEnv: %v", err)
	}
	if env["SECRET"] != "from-sops" || env["EMPTY"] != "" {
		t.Fatalf("env = %#v", env)
	}
}

func TestLoadAppEnvRejectsDotEnvAndSecretsTogether(t *testing.T) {
	appDir := t.TempDir()
	writeFile(t, filepath.Join(appDir, ".env"), "CUSTOM=plain\n")
	writeFile(t, filepath.Join(appDir, "secrets.enc.json"), `{"CUSTOM":"encrypted"}`+"\n")
	_, err := LoadAppEnv(context.Background(), appDir, false)
	if !errors.Is(err, ErrMultipleEnvSources) {
		t.Fatalf("LoadAppEnv error = %v, want ErrMultipleEnvSources", err)
	}
}

func writeFile(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// Tenants push symlinks with git; reading another app's env must fail, not
// load it or treat it as missing.
func TestLoadAppEnvRejectsSymlinksOutOfApp(t *testing.T) {
	other := t.TempDir()
	writeFile(t, filepath.Join(other, "victim"), "SECRET=other-app\n")
	for _, name := range []string{".env", "secrets.enc.json"} {
		appDir := t.TempDir()
		if err := os.Symlink(filepath.Join(other, "victim"), filepath.Join(appDir, name)); err != nil {
			t.Fatal(err)
		}
		if env, err := LoadAppEnv(context.Background(), appDir, false); err == nil {
			t.Fatalf("%s: LoadAppEnv = %#v, want error", name, env)
		}
	}
}

// TestLoadAppEnvRunsSOPSUnderLandrun runs the production path: sops confined
// by landrun, ciphertext on stdin, the age key passed by name and readable,
// and nothing else writable.
func TestLoadAppEnvRunsSOPSUnderLandrun(t *testing.T) {
	landrun, err := exec.LookPath("landrun")
	if err != nil {
		t.Skip("landrun not installed")
	}
	if err := sandbox.RequireLandlock(); err != nil {
		t.Skip(err)
	}
	appDir := t.TempDir()
	binDir := t.TempDir()
	writeFile(t, filepath.Join(appDir, "secrets.enc.json"), `{"sops":"metadata"}`+"\n")
	key := filepath.Join(t.TempDir(), "age.key")
	writeFile(t, key, "AGE-SECRET-KEY-TEST\n")
	escape := filepath.Join(t.TempDir(), "escape")
	fakeSOPS := filepath.Join(binDir, "sops")
	writeFile(t, fakeSOPS, "#!/bin/sh\nread -r line\ntouch "+escape+" || true\necho \"KEY=$(cat \"$SOPS_AGE_KEY_FILE\")\"\necho \"IN=$line\"\n")
	if err := os.Chmod(fakeSOPS, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+":"+filepath.Dir(landrun)+":/usr/bin:/bin")
	t.Setenv("SOPS_AGE_KEY_FILE", key)
	env, err := LoadAppEnv(context.Background(), appDir, true)
	if err != nil {
		t.Fatalf("LoadAppEnv: %v", err)
	}
	if env["KEY"] != "AGE-SECRET-KEY-TEST" || env["IN"] != `{"sops":"metadata"}` {
		t.Fatalf("env = %#v", env)
	}
	if _, err := os.Stat(escape); err == nil {
		t.Fatal("sops wrote outside its sandbox")
	}
}
