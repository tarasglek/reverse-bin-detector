package main

import (
	"context"
	"fmt"
	"os"

	"github.com/tarasglek/reverse-bin-detector/internal/detector"
)

func main() {
	if err := detector.Run(context.Background(), os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
