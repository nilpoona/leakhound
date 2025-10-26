package main

import (
	"context"
	"fmt"
	"log"
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

// WrapConfig embeds Config which contains sensitive fields
type WrapConfig struct {
	Config
	Description string
}

// NestedSafeConfig embeds SafeConfig which has no sensitive fields
type NestedSafeConfig struct {
	SafeConfig
	Extra string
}

func NewCustomLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, nil))
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
	slog.Info("config", config)                               // want "struct 'Config' contains sensitive fields and should not be logged entirely"
	slog.InfoContext(context.Background(), "config", config)  // want "struct 'Config' contains sensitive fields and should not be logged entirely"
	slog.Debug("config", config)                              // want "struct 'Config' contains sensitive fields and should not be logged entirely"
	slog.DebugContext(context.Background(), "config", config) // want "struct 'Config' contains sensitive fields and should not be logged entirely"
	slog.Warn("config", config)                               // want "struct 'Config' contains sensitive fields and should not be logged entirely"
	slog.WarnContext(context.Background(), "config", config)  // want "struct 'Config' contains sensitive fields and should not be logged entirely"
	slog.Error("config", config)                              // want "struct 'Config' contains sensitive fields and should not be logged entirely"
	slog.ErrorContext(context.Background(), "config", config) // want "struct 'Config' contains sensitive fields and should not be logged entirely"
	slog.Info("config", slog.Any("data", config))             // want "struct 'Config' contains sensitive fields and should not be logged entirely"
	fmt.Println("config:", config)                            // want "struct 'Config' contains sensitive fields and should not be logged entirely"

	// Safe struct should not trigger warnings
	slog.Info("safe", safeConfig)
	slog.Info("safe", slog.Any("data", safeConfig))
	slog.Info("safe", "data", safeConfig)

	// Custom logger tests
	ctx := context.Background()
	logger := NewCustomLogger()

	// Custom logger - direct field access (should be detected)
	logger.Info("secret", config.Secret)                                              // want "sensitive field 'Config.Secret' should not be logged"
	logger.Error("secret", config.Secret)                                             // want "sensitive field 'Config.Secret' should not be logged"
	logger.Warn("secret", config.Secret)                                              // want "sensitive field 'Config.Secret' should not be logged"
	logger.Debug("secret", config.Secret)                                             // want "sensitive field 'Config.Secret' should not be logged"
	logger.InfoContext(ctx, "secret", config.Secret)                                  // want "sensitive field 'Config.Secret' should not be logged"
	logger.ErrorContext(ctx, "secret", config.Secret)                                 // want "sensitive field 'Config.Secret' should not be logged"
	logger.WarnContext(ctx, "secret", config.Secret)                                  // want "sensitive field 'Config.Secret' should not be logged"
	logger.DebugContext(ctx, "secret", config.Secret)                                 // want "sensitive field 'Config.Secret' should not be logged"
	logger.Log(ctx, slog.LevelInfo, "secret", config.Secret)                          // want "sensitive field 'Config.Secret' should not be logged"
	logger.LogAttrs(ctx, slog.LevelInfo, "secret", slog.String("key", config.Secret)) // want "sensitive field 'Config.Secret' should not be logged"

	// Custom logger - entire struct (should be detected)
	logger.Info("config", config)                    // want "struct 'Config' contains sensitive fields and should not be logged entirely"
	logger.With("key", "val").Info("config", config) // want "struct 'Config' contains sensitive fields and should not be logged entirely"
	logger.Error("config", config)                   // want "struct 'Config' contains sensitive fields and should not be logged entirely"
	logger.Warn("config", config)                    // want "struct 'Config' contains sensitive fields and should not be logged entirely"
	logger.Debug("config", config)                   // want "struct 'Config' contains sensitive fields and should not be logged entirely"
	logger.InfoContext(ctx, "config", config)        // want "struct 'Config' contains sensitive fields and should not be logged entirely"
	logger.ErrorContext(ctx, "config", config)       // want "struct 'Config' contains sensitive fields and should not be logged entirely"
	logger.WarnContext(ctx, "config", config)        // want "struct 'Config' contains sensitive fields and should not be logged entirely"
	logger.DebugContext(ctx, "config", config)       // want "struct 'Config' contains sensitive fields and should not be logged entirely"

	// Custom logger - safe config (should NOT be detected)
	logger.Info("safe", safeConfig)
	logger.Error("safe", safeConfig)
	logger.InfoContext(ctx, "safe", safeConfig)

	// Standard log package tests
	// Direct field access (should be detected)
	log.Print("secret:", config.Secret)     // want "sensitive field 'Config.Secret' should not be logged"
	log.Printf("secret: %s", config.Secret) // want "sensitive field 'Config.Secret' should not be logged"
	log.Println("secret:", config.Secret)   // want "sensitive field 'Config.Secret' should not be logged"
	log.Fatal("secret:", config.Secret)     // want "sensitive field 'Config.Secret' should not be logged"
	log.Fatalf("secret: %s", config.Secret) // want "sensitive field 'Config.Secret' should not be logged"
	log.Fatalln("secret:", config.Secret)   // want "sensitive field 'Config.Secret' should not be logged"
	log.Panic("secret:", config.Secret)     // want "sensitive field 'Config.Secret' should not be logged"
	log.Panicf("secret: %s", config.Secret) // want "sensitive field 'Config.Secret' should not be logged"
	log.Panicln("secret:", config.Secret)   // want "sensitive field 'Config.Secret' should not be logged"

	// Entire struct with sensitive fields (should be detected)
	log.Print("config:", config)      // want "struct 'Config' contains sensitive fields and should not be logged entirely"
	log.Printf("config: %+v", config) // want "struct 'Config' contains sensitive fields and should not be logged entirely"
	log.Println("config:", config)    // want "struct 'Config' contains sensitive fields and should not be logged entirely"

	// Custom *log.Logger instance tests
	customLog := log.New(os.Stdout, "PREFIX: ", log.LstdFlags)

	// Custom *log.Logger - direct field access (should be detected)
	customLog.Print("secret:", config.Secret)     // want "sensitive field 'Config.Secret' should not be logged"
	customLog.Printf("secret: %s", config.Secret) // want "sensitive field 'Config.Secret' should not be logged"
	customLog.Println("secret:", config.Secret)   // want "sensitive field 'Config.Secret' should not be logged"
	customLog.Fatal("secret:", config.Secret)     // want "sensitive field 'Config.Secret' should not be logged"
	customLog.Fatalf("secret: %s", config.Secret) // want "sensitive field 'Config.Secret' should not be logged"
	customLog.Fatalln("secret:", config.Secret)   // want "sensitive field 'Config.Secret' should not be logged"
	customLog.Panic("secret:", config.Secret)     // want "sensitive field 'Config.Secret' should not be logged"
	customLog.Panicf("secret: %s", config.Secret) // want "sensitive field 'Config.Secret' should not be logged"
	customLog.Panicln("secret:", config.Secret)   // want "sensitive field 'Config.Secret' should not be logged"
	customLog.Output(2, config.Secret)            // want "sensitive field 'Config.Secret' should not be logged"

	// Custom *log.Logger - entire struct (should be detected)
	customLog.Print("config:", config)      // want "struct 'Config' contains sensitive fields and should not be logged entirely"
	customLog.Printf("config: %+v", config) // want "struct 'Config' contains sensitive fields and should not be logged entirely"
	customLog.Println("config:", config)    // want "struct 'Config' contains sensitive fields and should not be logged entirely"

	// Safe config with log package (should NOT be detected)
	log.Print("safe:", safeConfig)
	log.Println("safe:", safeConfig)
	customLog.Print("safe:", safeConfig)
	customLog.Println("safe:", safeConfig)

	// Nested struct tests
	wrapConfig := WrapConfig{
		Config:      config,
		Description: "wrapped config",
	}

	nestedSafeConfig := NestedSafeConfig{
		SafeConfig: safeConfig,
		Extra:      "extra info",
	}

	// Test nested struct with embedded sensitive struct - slog package
	slog.Info("wrapConfig", wrapConfig)                               // want "struct 'WrapConfig' contains sensitive fields and should not be logged entirely"
	slog.Info("wrapConfig.secret", wrapConfig.Config.Secret)          // want "sensitive field 'Config.Secret' should not be logged"
	slog.Info("wrapConfig", slog.Any("data", wrapConfig))             // want "struct 'WrapConfig' contains sensitive fields and should not be logged entirely"
	slog.InfoContext(context.Background(), "wrapConfig", wrapConfig)  // want "struct 'WrapConfig' contains sensitive fields and should not be logged entirely"
	slog.Debug("wrapConfig", wrapConfig)                              // want "struct 'WrapConfig' contains sensitive fields and should not be logged entirely"
	slog.DebugContext(context.Background(), "wrapConfig", wrapConfig) // want "struct 'WrapConfig' contains sensitive fields and should not be logged entirely"
	slog.Warn("wrapConfig", wrapConfig)                               // want "struct 'WrapConfig' contains sensitive fields and should not be logged entirely"
	slog.WarnContext(context.Background(), "wrapConfig", wrapConfig)  // want "struct 'WrapConfig' contains sensitive fields and should not be logged entirely"
	slog.Error("wrapConfig", wrapConfig)                              // want "struct 'WrapConfig' contains sensitive fields and should not be logged entirely"
	slog.ErrorContext(context.Background(), "wrapConfig", wrapConfig) // want "struct 'WrapConfig' contains sensitive fields and should not be logged entirely"

	// Test nested struct with embedded sensitive struct - fmt package
	fmt.Println("wrapConfig:", wrapConfig)                  // want "struct 'WrapConfig' contains sensitive fields and should not be logged entirely"
	fmt.Printf("wrapConfig: %+v", wrapConfig)               // want "struct 'WrapConfig' contains sensitive fields and should not be logged entirely"
	fmt.Print("wrapConfig:", wrapConfig)                    // want "struct 'WrapConfig' contains sensitive fields and should not be logged entirely"
	fmt.Fprint(os.Stdout, "wrapConfig:", wrapConfig)        // want "struct 'WrapConfig' contains sensitive fields and should not be logged entirely"
	fmt.Fprintf(os.Stdout, "wrapConfig: %+v", wrapConfig)   // want "struct 'WrapConfig' contains sensitive fields and should not be logged entirely"
	fmt.Fprintln(os.Stdout, "wrapConfig:", wrapConfig)      // want "struct 'WrapConfig' contains sensitive fields and should not be logged entirely"
	fmt.Println("nested secret:", wrapConfig.Config.Secret) // want "sensitive field 'Config.Secret' should not be logged"

	// Test nested struct with embedded sensitive struct - log package
	log.Print("wrapConfig:", wrapConfig)                    // want "struct 'WrapConfig' contains sensitive fields and should not be logged entirely"
	log.Printf("wrapConfig: %+v", wrapConfig)               // want "struct 'WrapConfig' contains sensitive fields and should not be logged entirely"
	log.Println("wrapConfig:", wrapConfig)                  // want "struct 'WrapConfig' contains sensitive fields and should not be logged entirely"
	customLog.Print("wrapConfig:", wrapConfig)              // want "struct 'WrapConfig' contains sensitive fields and should not be logged entirely"
	customLog.Printf("wrapConfig: %+v", wrapConfig)         // want "struct 'WrapConfig' contains sensitive fields and should not be logged entirely"
	customLog.Println("wrapConfig:", wrapConfig)            // want "struct 'WrapConfig' contains sensitive fields and should not be logged entirely"
	log.Println("nested secret:", wrapConfig.Config.Secret) // want "sensitive field 'Config.Secret' should not be logged"

	// Test nested struct with custom *slog.Logger
	logger.Info("wrapConfig", wrapConfig)                    // want "struct 'WrapConfig' contains sensitive fields and should not be logged entirely"
	logger.Error("wrapConfig", wrapConfig)                   // want "struct 'WrapConfig' contains sensitive fields and should not be logged entirely"
	logger.Warn("wrapConfig", wrapConfig)                    // want "struct 'WrapConfig' contains sensitive fields and should not be logged entirely"
	logger.Debug("wrapConfig", wrapConfig)                   // want "struct 'WrapConfig' contains sensitive fields and should not be logged entirely"
	logger.InfoContext(ctx, "wrapConfig", wrapConfig)        // want "struct 'WrapConfig' contains sensitive fields and should not be logged entirely"
	logger.With("key", "val").Info("wrapConfig", wrapConfig) // want "struct 'WrapConfig' contains sensitive fields and should not be logged entirely"
	logger.Info("nested secret", wrapConfig.Config.Secret)   // want "sensitive field 'Config.Secret' should not be logged"

	// Test nested safe struct (should NOT be detected)
	slog.Info("nestedSafe", nestedSafeConfig)
	fmt.Println("nestedSafe:", nestedSafeConfig)
	log.Println("nestedSafe:", nestedSafeConfig)
	logger.Info("nestedSafe", nestedSafeConfig)
	customLog.Println("nestedSafe:", nestedSafeConfig)
}
