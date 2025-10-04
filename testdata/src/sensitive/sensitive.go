package main

import (
	"log/slog"
)

type Config struct {
	Secret string `sensitive:"true"`
	Env    string
}

func main() {
	config := Config{
		Secret: "supersecret",
		Env:    "production",
	}

	slog.Info("env", config.Env)
	slog.Info("secret", config.Secret) // want "sensitive field 'Config.Secret' should not be logged"
}
