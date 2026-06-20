package detector

import (
	"context"
	"fmt"
	"io"
)

// Run executes the detector CLI.
func Run(ctx context.Context, args []string, stdout io.Writer) error {
	_ = ctx
	_ = args
	_, err := fmt.Fprintln(stdout, "{}")
	return err
}
