package buildconstraint

import "log/slog"

type CommonConfig struct {
	Name    string
	Version string
}

func commonLogging() {
	config := CommonConfig{
		Name:    "test-app",
		Version: "1.0.0",
	}

	// Safe logging - no sensitive fields
	slog.Info("app", config)
	slog.Info("name", config.Name)
	slog.Info("version", config.Version)
}
