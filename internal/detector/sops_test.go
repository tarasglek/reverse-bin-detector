package detector

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestLoadAppEnvDecryptsSecretsWithFakeSOPS(t *testing.T) {
	appDir := t.TempDir()
	writeFile(t, filepath.Join(appDir, "secrets.enc.json"), `{"sops":"metadata"}`+"\n")
	binDir := t.TempDir()
	fakeSOPS := filepath.Join(binDir, "sops")
	writeFile(t, fakeSOPS, "#!/bin/sh\nprintf '%s\\n' 'SECRET=from-sops' 'EMPTY='\n")
	if err := os.Chmod(fakeSOPS, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	env, err := LoadAppEnv(context.Background(), appDir, nil)
	if err != nil {
		t.Fatalf("LoadAppEnv: %v", err)
	}
	want := map[string]string{"SECRET": "from-sops", "EMPTY": ""}
	if !reflect.DeepEqual(env, want) {
		t.Fatalf("env = %#v, want %#v", env, want)
	}
}
