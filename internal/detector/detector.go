package detector

import (
	"context"
	"encoding/json"
	"io"

	"github.com/tarasglek/caddy-reverse-bin/detectorschema"
)

// Run executes the detector CLI.
func Run(ctx context.Context, args []string, stdout io.Writer) error {
	_ = ctx
	_ = args

	output := detectorschema.DetectorOutput{}
	encoder := json.NewEncoder(stdout)
	return encoder.Encode(output)
}
