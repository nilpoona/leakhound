package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
)

type Config struct {
	Secret string `sensitive:"true"`
	Env    string
}

type SafeConfig struct {
	Name string
	Mode string
}

// CustomLogger is a custom logger wrapper for testing custom logger detection
type CustomLogger struct {
	logger *slog.Logger
}

func NewCustomLogger() *CustomLogger {
	return &CustomLogger{
		logger: slog.New(slog.NewTextHandler(os.Stdout, nil)),
	}
}

func (l *CustomLogger) Debug(msg string, args ...any) {
	l.logger.Debug(msg, args...)
}

func (l *CustomLogger) DebugContext(ctx context.Context, msg string, args ...any) {
	l.logger.DebugContext(ctx, msg, args...)
}

func (l *CustomLogger) Error(msg string, args ...any) {
	l.logger.Error(msg, args...)
}

func (l *CustomLogger) ErrorContext(ctx context.Context, msg string, args ...any) {
	l.logger.ErrorContext(ctx, msg, args...)
}

func (l *CustomLogger) Info(msg string, args ...any) {
	l.logger.Info(msg, args...)
}

func (l *CustomLogger) InfoContext(ctx context.Context, msg string, args ...any) {
	l.logger.InfoContext(ctx, msg, args...)
}

func (l *CustomLogger) Warn(msg string, args ...any) {
	l.logger.Warn(msg, args...)
}

func (l *CustomLogger) WarnContext(ctx context.Context, msg string, args ...any) {
	l.logger.WarnContext(ctx, msg, args...)
}

func (l *CustomLogger) Log(ctx context.Context, level slog.Level, msg string, args ...any) {
	l.logger.Log(ctx, level, msg, args...)
}

func (l *CustomLogger) LogAttrs(ctx context.Context, level slog.Level, msg string, attrs ...slog.Attr) {
	l.logger.LogAttrs(ctx, level, msg, attrs...)
}

func main() {
	config := Config{
		Secret: "supersecret",
		Env:    "production",
	}

	safeConfig := SafeConfig{
		Name: "app",
		Mode: "production",
	}

	// Non-sensitive field logging should be fine
	slog.Info("env", config.Env)
	fmt.Println("env:", config.Env)

	slog.Info("secret", config.Secret)                        // want "sensitive field 'Config.Secret' should not be logged"
	slog.Info("secret", slog.String("config", config.Secret)) // want "sensitive field 'Config.Secret' should not be logged"
	slog.Info("secretPtr", &config.Secret)                    // want "sensitive field 'Config.Secret' should not be logged"

	fmt.Fprint(os.Stdout, "secret: ", config.Secret)    // want "sensitive field 'Config.Secret' should not be logged"
	fmt.Fprintf(os.Stdout, "secret: %s", config.Secret) // want "sensitive field 'Config.Secret' should not be logged"
	fmt.Fprintln(os.Stdout, "secret: ", config.Secret)  // want "sensitive field 'Config.Secret' should not be logged"
	fmt.Print("secret:", config.Secret)                 // want "sensitive field 'Config.Secret' should not be logged"
	fmt.Printf("secret: %s", config.Secret)             // want "sensitive field 'Config.Secret' should not be logged"
	fmt.Println("secret:", config.Secret)               // want "sensitive field 'Config.Secret' should not be logged"

	// Test struct with sensitive fields passed entirely
	slog.Info("config", config)                   // want "struct 'Config' contains sensitive fields and should not be logged entirely"
	slog.Info("config", slog.Any("data", config)) // want "struct 'Config' contains sensitive fields and should not be logged entirely"
	fmt.Println("config:", config)                // want "struct 'Config' contains sensitive fields and should not be logged entirely"

	// Safe struct should not trigger warnings
	slog.Info("safe", safeConfig)
	slog.Info("safe", slog.Any("data", safeConfig))
	slog.Info("safe", "data", safeConfig)

	// Custom logger tests
	ctx := context.Background()
	logger := NewCustomLogger()

	// Custom logger - direct field access (should be detected)
	logger.Info("secret", config.Secret)                        // want "sensitive field 'Config.Secret' should not be logged"
	logger.Error("secret", config.Secret)                       // want "sensitive field 'Config.Secret' should not be logged"
	logger.Warn("secret", config.Secret)                        // want "sensitive field 'Config.Secret' should not be logged"
	logger.Debug("secret", config.Secret)                       // want "sensitive field 'Config.Secret' should not be logged"
	logger.InfoContext(ctx, "secret", config.Secret)            // want "sensitive field 'Config.Secret' should not be logged"
	logger.ErrorContext(ctx, "secret", config.Secret)           // want "sensitive field 'Config.Secret' should not be logged"
	logger.WarnContext(ctx, "secret", config.Secret)            // want "sensitive field 'Config.Secret' should not be logged"
	logger.DebugContext(ctx, "secret", config.Secret)           // want "sensitive field 'Config.Secret' should not be logged"
	logger.Log(ctx, slog.LevelInfo, "secret", config.Secret)    // want "sensitive field 'Config.Secret' should not be logged"
	logger.LogAttrs(ctx, slog.LevelInfo, "secret", slog.String("key", config.Secret)) // want "sensitive field 'Config.Secret' should not be logged"

	// Custom logger - entire struct (should be detected)
	logger.Info("config", config)                               // want "struct 'Config' contains sensitive fields and should not be logged entirely"
	logger.Error("config", config)                              // want "struct 'Config' contains sensitive fields and should not be logged entirely"
	logger.Warn("config", config)                               // want "struct 'Config' contains sensitive fields and should not be logged entirely"
	logger.Debug("config", config)                              // want "struct 'Config' contains sensitive fields and should not be logged entirely"
	logger.InfoContext(ctx, "config", config)                   // want "struct 'Config' contains sensitive fields and should not be logged entirely"
	logger.ErrorContext(ctx, "config", config)                  // want "struct 'Config' contains sensitive fields and should not be logged entirely"
	logger.WarnContext(ctx, "config", config)                   // want "struct 'Config' contains sensitive fields and should not be logged entirely"
	logger.DebugContext(ctx, "config", config)                  // want "struct 'Config' contains sensitive fields and should not be logged entirely"

	// Custom logger - safe config (should NOT be detected)
	logger.Info("safe", safeConfig)
	logger.Error("safe", safeConfig)
	logger.InfoContext(ctx, "safe", safeConfig)
}
