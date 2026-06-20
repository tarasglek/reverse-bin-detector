package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/tarasglek/caddy-reverse-bin/detectorschema"
)

func TestCLIOutputParsesWithDetectorSchema(t *testing.T) {
	appDir := t.TempDir()
	mainPy := filepath.Join(appDir, "main.py")
	if err := os.WriteFile(mainPy, []byte("#!/usr/bin/env python3\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("go", "run", ".", "--allow-unsafe-no-landlock", appDir)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		t.Fatalf("run detector CLI: %v\nstderr: %s", err, stderr.String())
	}

	if _, err := detectorschema.Parse(stdout.Bytes()); err != nil {
		t.Fatalf("parse detector output: %v\nstdout: %s", err, stdout.String())
	}
}
