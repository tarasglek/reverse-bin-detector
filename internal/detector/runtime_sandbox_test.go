package detector

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveAppEmitsRuntimeLandrunWrapper(t *testing.T) {
	appDir := makeExecutableMainPyApp(t)
	dataDir := filepath.Join(appDir, "data")
	if err := os.Mkdir(dataDir, 0o755); err != nil {
		t.Fatal(err)
	}
	resolved, err := ResolveAppWithOptions(context.Background(), appDir, map[string]string{"REVERSE_BIN_PORT": "7777"}, Options{})
	if err != nil {
		t.Fatalf("ResolveAppWithOptions: %v", err)
	}
	command := strings.Join(resolved.Executable, " ")
	for _, want := range []string{"landrun", "--rox", appDir, "--rw", dataDir, "--env", "REVERSE_BIN_PORT=7777", "--bind-tcp", "7777", "./main.py"} {
		if !strings.Contains(command, want) {
			t.Fatalf("command %q missing %q", command, want)
		}
	}
}

func TestResolveAppCanDisableRuntimeSandbox(t *testing.T) {
	appDir := makeExecutableMainPyApp(t)
	resolved, err := ResolveAppWithOptions(context.Background(), appDir, map[string]string{"REVERSE_BIN_PORT": "7777"}, Options{NoRuntimeSandbox: true})
	if err != nil {
		t.Fatalf("ResolveAppWithOptions: %v", err)
	}
	if len(resolved.Executable) == 0 || resolved.Executable[0] == "landrun" {
		t.Fatalf("Executable = %#v, want unwrapped app command", resolved.Executable)
	}
}
