//go:build linux
// +build linux

package buildconstraint

import "log/slog"

type LinuxConfig struct {
	Secret   string `sensitive:"true"`
	Endpoint string
}

func linuxSpecificLogging() {
	config := LinuxConfig{
		Secret:   "linux-secret",
		Endpoint: "linux.example.com",
	}

	slog.Info("endpoint", config.Endpoint)
	slog.Info("secret", config.Secret) // want "sensitive field 'LinuxConfig.Secret' should not be logged"
	slog.Info("config", config)        // want "struct 'LinuxConfig' contains sensitive fields and should not be logged entirely"
}
