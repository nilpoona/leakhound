package main

import (
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
}
