package detector

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

var ErrMultipleEnvSources = errors.New("multiple env sources")

type SOPSDecryptFunc func(ctx context.Context, path string) (string, error)

func LoadAppEnv(ctx context.Context, appDir string, decrypt SOPSDecryptFunc) (map[string]string, error) {
	dotEnvPath := filepath.Join(appDir, ".env")
	secretsPath := filepath.Join(appDir, "secrets.enc.json")

	hasDotEnv, err := fileExists(dotEnvPath)
	if err != nil {
		return nil, err
	}
	hasSecrets, err := fileExists(secretsPath)
	if err != nil {
		return nil, err
	}
	if hasDotEnv && hasSecrets {
		return nil, fmt.Errorf("%w: cannot use both .env and secrets.enc.json", ErrMultipleEnvSources)
	}
	if !hasDotEnv && !hasSecrets {
		return map[string]string{}, nil
	}

	var dotenv string
	if hasDotEnv {
		data, err := os.ReadFile(dotEnvPath)
		if err != nil {
			return nil, err
		}
		dotenv = string(data)
	} else {
		if decrypt == nil {
			var err error
			decrypt, err = ResolveSOPSDecryptFunc()
			if err != nil {
				return nil, fmt.Errorf("decrypt secrets.enc.json: %w", err)
			}
		}
		var err error
		dotenv, err = decrypt(ctx, secretsPath)
		if err != nil {
			return nil, fmt.Errorf("decrypt secrets.enc.json: %w", err)
		}
	}

	return parseDotEnv(dotenv), nil
}

func ResolveSOPSDecryptFunc() (SOPSDecryptFunc, error) {
	sopsPath, err := exec.LookPath("sops")
	if err != nil {
		return nil, err
	}
	return SOPSDecryptFuncForPath(sopsPath), nil
}

func SOPSDecryptFuncForPath(sopsPath string) SOPSDecryptFunc {
	return func(ctx context.Context, path string) (string, error) {
		cmd := exec.CommandContext(ctx, sopsPath, "--decrypt", "--input-type", "json", "--output-type", "dotenv", path)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		stdout, err := cmd.Output()
		if err != nil {
			msg := strings.TrimSpace(stderr.String())
			if msg != "" {
				return "", fmt.Errorf("%w: %s", err, msg)
			}
			return "", err
		}
		return string(stdout), nil
	}
}

func fileExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func parseDotEnv(content string) map[string]string {
	env := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, value, ok := strings.Cut(line, "=")
		if !ok || name == "" {
			continue
		}
		env[name] = trimEnvValue(value)
	}
	return env
}

func trimEnvValue(value string) string {
	value = strings.TrimSpace(value)
	if len(value) >= 2 {
		quote := value[0]
		if (quote == '\'' || quote == '"') && value[len(value)-1] == quote {
			return value[1 : len(value)-1]
		}
	}
	return value
}
