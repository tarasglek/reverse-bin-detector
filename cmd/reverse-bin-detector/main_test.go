package main

import (
	"bytes"
	"os/exec"
	"testing"

	"github.com/tarasglek/caddy-reverse-bin/detectorschema"
)

func TestCLIOutputParsesWithDetectorSchema(t *testing.T) {
	cmd := exec.Command("go", "run", ".")
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = new(bytes.Buffer)

	if err := cmd.Run(); err != nil {
		t.Fatalf("run detector CLI: %v\nstderr: %s", err, cmd.Stderr)
	}

	if _, err := detectorschema.Parse(stdout.Bytes()); err != nil {
		t.Fatalf("parse detector output: %v\nstdout: %s", err, stdout.String())
	}
}
