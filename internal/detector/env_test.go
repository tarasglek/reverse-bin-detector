package detector

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadAppEnvLoadsDotEnv(t *testing.T) {
	appDir := t.TempDir()
	writeFile(t, filepath.Join(appDir, ".env"), "CUSTOM=1\nQUOTED='hello world'\nREVERSE_BIN_PORT=\n")
	env, err := LoadAppEnv(context.Background(), appDir)
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
	writeFile(t, fakeSOPS, "#!/bin/sh\nprintf '%s\\n' 'SECRET=from-sops' 'EMPTY='\n")
	if err := os.Chmod(fakeSOPS, 0o755); err != nil {
		t.Fatalf("chmod fake sops: %v", err)
	}
	t.Setenv("PATH", binDir)
	env, err := LoadAppEnv(context.Background(), appDir)
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
	_, err := LoadAppEnv(context.Background(), appDir)
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
