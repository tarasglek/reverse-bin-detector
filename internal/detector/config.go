package detector

import (
	"fmt"
	"strconv"
	"strings"
)

const (
	KeyReverseBinCommand      = "REVERSE_BIN_COMMAND"
	KeyListen                 = "LISTEN"
	KeyReverseBinHost         = "REVERSE_BIN_HOST"
	KeyReverseBinPort         = "REVERSE_BIN_PORT"
	KeySocketPath             = "SOCKET_PATH"
	KeyReverseBinHealthMethod = "REVERSE_BIN_HEALTH_METHOD"
	KeyReverseBinHealthPath   = "REVERSE_BIN_HEALTH_PATH"
	KeyReverseBinHealthStatus = "REVERSE_BIN_HEALTH_STATUS"
)

type EnvAppConfig struct {
	Command        []string
	Listen         *string
	ReverseBinHost *string
	ReverseBinPort *string
	SocketPath     *string
	HealthMethod   *string
	HealthPath     *string
	HealthStatus   *int
}

func LoadEnvAppConfig(env map[string]string) (EnvAppConfig, error) {
	var cfg EnvAppConfig
	if command, ok := env[KeyReverseBinCommand]; ok && command != "" {
		cfg.Command = []string{"sh", "-c", command}
	}
	cfg.Listen = stringPtrFromMap(env, KeyListen)
	cfg.ReverseBinHost = stringPtrFromMap(env, KeyReverseBinHost)
	cfg.ReverseBinPort = stringPtrFromMap(env, KeyReverseBinPort)
	cfg.SocketPath = stringPtrFromMap(env, KeySocketPath)

	if method, ok := env[KeyReverseBinHealthMethod]; ok {
		method = strings.ToUpper(strings.TrimSpace(method))
		cfg.HealthMethod = &method
	}
	cfg.HealthPath = stringPtrFromMap(env, KeyReverseBinHealthPath)
	if statusText, ok := env[KeyReverseBinHealthStatus]; ok {
		status, err := strconv.Atoi(strings.TrimSpace(statusText))
		if err != nil {
			return EnvAppConfig{}, fmt.Errorf("%s must be an integer", KeyReverseBinHealthStatus)
		}
		if status < 100 || status > 599 {
			return EnvAppConfig{}, fmt.Errorf("%s must be 100 through 599", KeyReverseBinHealthStatus)
		}
		cfg.HealthStatus = &status
	}

	if hasTCPConfig(cfg) && cfg.SocketPath != nil {
		return EnvAppConfig{}, fmt.Errorf("both TCP listener config and SOCKET_PATH are set")
	}
	if cfg.Listen != nil && cfg.ReverseBinPort != nil {
		return EnvAppConfig{}, fmt.Errorf("LISTEN and REVERSE_BIN_PORT cannot both be set")
	}
	if (cfg.HealthMethod == nil) != (cfg.HealthPath == nil) {
		return EnvAppConfig{}, fmt.Errorf("%s and %s must be set together", KeyReverseBinHealthMethod, KeyReverseBinHealthPath)
	}
	if cfg.HealthStatus != nil && (cfg.HealthMethod == nil || cfg.HealthPath == nil) {
		return EnvAppConfig{}, fmt.Errorf("%s requires %s and %s", KeyReverseBinHealthStatus, KeyReverseBinHealthMethod, KeyReverseBinHealthPath)
	}
	return cfg, nil
}

func stringPtrFromMap(env map[string]string, key string) *string {
	value, ok := env[key]
	if !ok {
		return nil
	}
	return &value
}

func hasTCPConfig(cfg EnvAppConfig) bool {
	return cfg.Listen != nil || cfg.ReverseBinHost != nil || cfg.ReverseBinPort != nil
}
