package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"

	"github.com/tarasglek/reverse-bin-detector/internal/detector"
)

func main() {
	if err := detector.Run(context.Background(), os.Args[1:], os.Stdout); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
