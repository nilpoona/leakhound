//go:build debug
// +build debug

package buildconstraint

import "log/slog"

type DebugConfig struct {
	Token     string `sensitive:"true"`
	DebugMode bool
}

func debugLogging() {
	config := DebugConfig{
		Token:     "debug-token",
		DebugMode: true,
	}

	slog.Info("debug", config.DebugMode)
	slog.Info("token", config.Token)  // want "sensitive field 'DebugConfig.Token' should not be logged"
	slog.Info("debug-config", config) // want "struct 'DebugConfig' contains sensitive fields and should not be logged entirely"
}
