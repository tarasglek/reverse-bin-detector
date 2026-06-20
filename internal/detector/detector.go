package detector

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/tarasglek/caddy-reverse-bin/detectorschema"
	"github.com/tarasglek/reverse-bin-detector/internal/sandbox"
)

// Run executes the detector CLI.
func Run(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("reverse-bin-detector", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	allowUnsafeNoLandlock := fs.Bool("allow-unsafe-no-landlock", false, "disable detection Landlock sandbox")
	noRuntimeSandbox := fs.Bool("no-runtime-sandbox", false, "emit backend command without runtime sandbox wrapper")
	showVersion := fs.Bool("version", false, "print version and exit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *showVersion {
		_, err := fmt.Fprintf(stdout, "%s %s %s\n", Version, Commit, BuildDate)
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: reverse-bin-detector [--allow-unsafe-no-landlock] APP_DIR")
	}
	appDir := fs.Arg(0)
	decrypt, err := prepareSOPSDecrypt(ctx, appDir)
	if err != nil {
		return err
	}
	if !*allowUnsafeNoLandlock {
		policy := sandbox.DetectionPolicy(appDir, environMap(os.Environ()))
		if err := sandbox.Apply(policy, sandbox.LandlockOptions{}); err != nil {
			return err
		}
	}

	env, err := LoadAppEnv(ctx, appDir, decrypt)
	if err != nil {
		return err
	}
	resolved, err := ResolveAppWithOptions(ctx, appDir, env, Options{NoRuntimeSandbox: *noRuntimeSandbox})
	if err != nil {
		return err
	}

	output := detectorOutputFromResolved(resolved)
	encoder := json.NewEncoder(stdout)
	return encoder.Encode(output)
}

func prepareSOPSDecrypt(ctx context.Context, appDir string) (SOPSDecryptFunc, error) {
	_ = ctx
	hasSecrets, err := fileExists(filepath.Join(appDir, "secrets.enc.json"))
	if err != nil || !hasSecrets {
		return nil, err
	}
	return ResolveSOPSDecryptFunc()
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
