package detector

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/tarasglek/caddy-reverse-bin/detectorschema"
	"github.com/tarasglek/reverse-bin-detector/internal/sandbox"
)

// Run executes the detector CLI.
func Run(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("reverse-bin-detector", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	allowUnsafeNoLandlock := fs.Bool("allow-unsafe-no-landlock", false, "disable detection Landlock sandbox")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: reverse-bin-detector [--allow-unsafe-no-landlock] APP_DIR")
	}
	appDir := fs.Arg(0)
	if !*allowUnsafeNoLandlock {
		policy := sandbox.DetectionPolicy(appDir, environMap(os.Environ()))
		if err := sandbox.Apply(policy, sandbox.LandlockOptions{}); err != nil {
			return err
		}
	}

	env, err := LoadAppEnv(ctx, appDir, nil)
	if err != nil {
		return err
	}
	resolved, err := ResolveApp(ctx, appDir, env)
	if err != nil {
		return err
	}

	output := detectorOutputFromResolved(resolved)
	encoder := json.NewEncoder(stdout)
	return encoder.Encode(output)
}

func environMap(environ []string) map[string]string {
	env := make(map[string]string, len(environ))
	for _, entry := range environ {
		name, value, ok := strings.Cut(entry, "=")
		if ok {
			env[name] = value
		}
	}
	return env
}

func detectorOutputFromResolved(resolved ResolvedApp) detectorschema.DetectorOutput {
	output := detectorschema.DetectorOutput{
		Executable:       &resolved.Executable,
		WorkingDirectory: &resolved.WorkingDirectory,
		Envs:             &resolved.Envs,
		ReverseProxyTo:   &resolved.ReverseProxyTo,
		HealthMethod:     resolved.HealthMethod,
		HealthPath:       resolved.HealthPath,
		HealthStatus:     resolved.HealthStatus,
	}
	return output
}
