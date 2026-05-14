package config

import (
	"os"
)

type AgentConfig struct {
	BackendURL string
	DeviceId   string
	LogLevel   string
}

func LoadConfig() *AgentConfig {
	deviceId, err := os.Hostname()
	if err != nil {
		deviceId = "Unknown-Linux"
	}

	backendURL := os.Getenv("FENRIR_BACKEND_URL")
	if backendURL == "" {
		backendURL = "http://localhost:3000/api/v1/telemetry"
	}

	return &AgentConfig{
		BackendURL: backendURL,
		DeviceId:   deviceId,
		LogLevel:   "INFO",
	}
}
