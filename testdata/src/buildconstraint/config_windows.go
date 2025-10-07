//go:build windows
// +build windows

package buildconstraint

import "log/slog"

type WindowsConfig struct {
	APIKey   string `sensitive:"true"`
	Registry string
}

func windowsSpecificLogging() {
	config := WindowsConfig{
		APIKey:   "windows-api-key",
		Registry: "HKEY_LOCAL_MACHINE",
	}

	slog.Info("registry", config.Registry)
	slog.Info("apikey", config.APIKey) // want "sensitive field 'WindowsConfig.APIKey' should not be logged"
	slog.Info("config", config)        // want "struct 'WindowsConfig' contains sensitive fields and should not be logged entirely"
}
