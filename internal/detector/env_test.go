package detector

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestLoadAppEnvLoadsDotEnv(t *testing.T) {
	appDir := t.TempDir()
	writeFile(t, filepath.Join(appDir, ".env"), "CUSTOM=1\nQUOTED=hello world\n")

	env, err := LoadAppEnv(context.Background(), appDir, nil)
	if err != nil {
		t.Fatalf("LoadAppEnv: %v", err)
	}

	want := map[string]string{"CUSTOM": "1", "QUOTED": "hello world"}
	if !reflect.DeepEqual(env, want) {
		t.Fatalf("env = %#v, want %#v", env, want)
	}
}

func TestLoadAppEnvPreservesBlankDotEnvValues(t *testing.T) {
	appDir := t.TempDir()
	writeFile(t, filepath.Join(appDir, ".env"), "REVERSE_BIN_PORT=\n")

	env, err := LoadAppEnv(context.Background(), appDir, nil)
	if err != nil {
		t.Fatalf("LoadAppEnv: %v", err)
	}

	if got, ok := env["REVERSE_BIN_PORT"]; !ok || got != "" {
		t.Fatalf("REVERSE_BIN_PORT = %q, present %v; want blank present", got, ok)
	}
}

func TestLoadAppEnvLoadsSecretsEncJSONThroughDecryptFunc(t *testing.T) {
	appDir := t.TempDir()
	secretPath := filepath.Join(appDir, "secrets.enc.json")
	writeFile(t, secretPath, `{"sops":"metadata"}`+"\n")

	var gotPath string
	decrypt := func(ctx context.Context, path string) (string, error) {
		gotPath = path
		return "SECRET=decrypted\nEMPTY=\nIGNORED\n", nil
	}

	env, err := LoadAppEnv(context.Background(), appDir, decrypt)
	if err != nil {
		t.Fatalf("LoadAppEnv: %v", err)
	}

	want := map[string]string{"SECRET": "decrypted", "EMPTY": ""}
	if !reflect.DeepEqual(env, want) {
		t.Fatalf("env = %#v, want %#v", env, want)
	}
	if gotPath != secretPath {
		t.Fatalf("decrypt path = %q, want %q", gotPath, secretPath)
	}
}

func TestLoadAppEnvRejectsDotEnvAndSecretsTogether(t *testing.T) {
	appDir := t.TempDir()
	writeFile(t, filepath.Join(appDir, ".env"), "CUSTOM=plain\n")
	writeFile(t, filepath.Join(appDir, "secrets.enc.json"), `{"CUSTOM":"encrypted"}`+"\n")

	_, err := LoadAppEnv(context.Background(), appDir, func(context.Context, string) (string, error) {
		return "CUSTOM=encrypted\n", nil
	})
	if err == nil {
		t.Fatal("LoadAppEnv error = nil, want error")
	}
	if !errors.Is(err, ErrMultipleEnvSources) {
		t.Fatalf("LoadAppEnv error = %v, want ErrMultipleEnvSources", err)
	}
}

func writeFile(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
