package detector

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

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
	if !*allowUnsafeNoLandlock {
		if err := sandbox.ApplyDetection(appDir, environMap(os.Environ()), sandbox.LandlockOptions{}); err != nil {
			return err
		}
	}
	env, err := LoadAppEnv(ctx, appDir)
	if err != nil {
		return err
	}
	out, err := ResolveAppWithRuntimeSandbox(ctx, appDir, env, !*noRuntimeSandbox)
	if err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(out)
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
