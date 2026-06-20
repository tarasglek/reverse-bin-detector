package detector

import (
	"reflect"
	"testing"
)

func TestLoadEnvAppConfigReadsReverseBinCommandAsShellCommand(t *testing.T) {
	cfg, err := LoadEnvAppConfig(map[string]string{"REVERSE_BIN_COMMAND": "python3 server.py"})
	if err != nil {
		t.Fatalf("LoadEnvAppConfig: %v", err)
	}
	if !reflect.DeepEqual(cfg.Command, []string{"sh", "-c", "python3 server.py"}) {
		t.Fatalf("Command = %#v", cfg.Command)
	}
}

func TestLoadEnvAppConfigReadsListen(t *testing.T) {
	cfg, err := LoadEnvAppConfig(map[string]string{"LISTEN": "8080"})
	if err != nil {
		t.Fatalf("LoadEnvAppConfig: %v", err)
	}
	if cfg.Listen == nil || *cfg.Listen != "8080" {
		t.Fatalf("Listen = %#v, want 8080", cfg.Listen)
	}
}

func TestLoadEnvAppConfigReadsReverseBinHostPort(t *testing.T) {
	cfg, err := LoadEnvAppConfig(map[string]string{"REVERSE_BIN_HOST": "0.0.0.0", "REVERSE_BIN_PORT": "9999"})
	if err != nil {
		t.Fatalf("LoadEnvAppConfig: %v", err)
	}
	if cfg.ReverseBinHost == nil || *cfg.ReverseBinHost != "0.0.0.0" {
		t.Fatalf("ReverseBinHost = %#v", cfg.ReverseBinHost)
	}
	if cfg.ReverseBinPort == nil || *cfg.ReverseBinPort != "9999" {
		t.Fatalf("ReverseBinPort = %#v", cfg.ReverseBinPort)
	}
}

func TestLoadEnvAppConfigReadsSocketPath(t *testing.T) {
	cfg, err := LoadEnvAppConfig(map[string]string{"SOCKET_PATH": "data/app.sock"})
	if err != nil {
		t.Fatalf("LoadEnvAppConfig: %v", err)
	}
	if cfg.SocketPath == nil || *cfg.SocketPath != "data/app.sock" {
		t.Fatalf("SocketPath = %#v, want data/app.sock", cfg.SocketPath)
	}
}

func TestLoadEnvAppConfigReadsHealthMethodPathStatus(t *testing.T) {
	cfg, err := LoadEnvAppConfig(map[string]string{
		"REVERSE_BIN_HEALTH_METHOD": "get",
		"REVERSE_BIN_HEALTH_PATH":   "/health",
		"REVERSE_BIN_HEALTH_STATUS": "204",
	})
	if err != nil {
		t.Fatalf("LoadEnvAppConfig: %v", err)
	}
	if cfg.HealthMethod == nil || *cfg.HealthMethod != "GET" {
		t.Fatalf("HealthMethod = %#v, want GET", cfg.HealthMethod)
	}
	if cfg.HealthPath == nil || *cfg.HealthPath != "/health" {
		t.Fatalf("HealthPath = %#v, want /health", cfg.HealthPath)
	}
	if cfg.HealthStatus == nil || *cfg.HealthStatus != 204 {
		t.Fatalf("HealthStatus = %#v, want 204", cfg.HealthStatus)
	}
}

func TestLoadEnvAppConfigRejectsBadCombinations(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
	}{
		{"listen and socket", map[string]string{"LISTEN": "8080", "SOCKET_PATH": "data/app.sock"}},
		{"listen and reverse bin port", map[string]string{"LISTEN": "8080", "REVERSE_BIN_PORT": "9999"}},
		{"health method without path", map[string]string{"REVERSE_BIN_HEALTH_METHOD": "GET"}},
		{"health path without method", map[string]string{"REVERSE_BIN_HEALTH_PATH": "/health"}},
		{"health status without probe", map[string]string{"REVERSE_BIN_HEALTH_STATUS": "200"}},
		{"bad status text", map[string]string{"REVERSE_BIN_HEALTH_METHOD": "GET", "REVERSE_BIN_HEALTH_PATH": "/health", "REVERSE_BIN_HEALTH_STATUS": "ok"}},
		{"bad status range", map[string]string{"REVERSE_BIN_HEALTH_METHOD": "GET", "REVERSE_BIN_HEALTH_PATH": "/health", "REVERSE_BIN_HEALTH_STATUS": "600"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := LoadEnvAppConfig(tt.env); err == nil {
				t.Fatal("LoadEnvAppConfig error = nil, want error")
			}
		})
	}
}
