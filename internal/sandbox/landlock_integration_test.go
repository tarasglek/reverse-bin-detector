//go:build linux

package sandbox

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestDetectionLandlockSubprocessRestrictions(t *testing.T) {
	appDir := t.TempDir()
	writeSandboxTestFile(t, filepath.Join(appDir, "allowed.txt"), "ok")
	outsideDir := t.TempDir()
	outsideFile := filepath.Join(outsideDir, "outside.txt")
	writeSandboxTestFile(t, outsideFile, "secret")

	for _, mode := range []string{"read-app", "write-app", "read-outside", "listen", "dial"} {
		t.Run(mode, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=TestDetectionLandlockSubprocessHelper", "--")
			cmd.Env = append(os.Environ(),
				"SANDBOX_HELPER=1",
				"SANDBOX_MODE="+mode,
				"SANDBOX_APP_DIR="+appDir,
				"SANDBOX_OUTSIDE_FILE="+outsideFile,
			)
			out, err := cmd.CombinedOutput()
			text := string(out)
			if strings.Contains(text, "SKIP landlock") {
				t.Skip(text)
			}
			switch mode {
			case "read-app", "listen":
				if err != nil {
					t.Fatalf("helper failed: %v\n%s", err, text)
				}
			case "write-app", "read-outside", "dial":
				if err == nil {
					t.Fatalf("helper succeeded, want denial\n%s", text)
				}
				if !strings.Contains(text, "permission denied") && !strings.Contains(text, "operation not permitted") {
					t.Fatalf("helper output = %q, want permission denial", text)
				}
			}
		})
	}
}

func TestDetectionLandlockSubprocessHelper(t *testing.T) {
	if os.Getenv("SANDBOX_HELPER") != "1" {
		return
	}
	appDir := os.Getenv("SANDBOX_APP_DIR")
	if err := ApplyDetection(appDir, nil, LandlockOptions{}); err != nil {
		fmt.Printf("SKIP landlock unavailable: %v\n", err)
		os.Exit(0)
	}

	var err error
	switch os.Getenv("SANDBOX_MODE") {
	case "read-app":
		_, err = os.ReadFile(filepath.Join(appDir, "allowed.txt"))
	case "write-app":
		err = os.WriteFile(filepath.Join(appDir, "denied.txt"), []byte("no"), 0o644)
	case "read-outside":
		_, err = os.ReadFile(os.Getenv("SANDBOX_OUTSIDE_FILE"))
	case "listen":
		var lc net.ListenConfig
		lc.SetMultipathTCP(false)
		ln, listenErr := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
		if listenErr == nil {
			_ = ln.Close()
		}
		err = listenErr
	case "dial":
		dialer := net.Dialer{}
		conn, dialErr := dialer.DialContext(context.Background(), "tcp", "127.0.0.1:9")
		if dialErr == nil {
			_ = conn.Close()
		}
		err = dialErr
	default:
		err = fmt.Errorf("unknown mode")
	}
	if err != nil {
		if errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) {
			fmt.Printf("permission denied: %v\n", err)
			os.Exit(2)
		}
		fmt.Printf("error: %v\n", err)
		os.Exit(3)
	}
	os.Exit(0)
}

func writeSandboxTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
