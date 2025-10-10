package main

import (
	"log/slog"

	"crosspackage/models"
)

func TestCrossPackageDetection() {
	user := models.User{
		Name:     "John",
		Email:    "john@example.com",
		Password: "secret123",
		APIToken: "token123",
	}

	safeStruct := models.SafeStruct{
		PublicData: "public",
		ID:         1,
	}

	// These should be detected as sensitive field access
	slog.Info("password", user.Password) // want "sensitive field 'User.Password' should not be logged"
	slog.Info("token", user.APIToken)    // want "sensitive field 'User.APIToken' should not be logged"

	// Entire struct with sensitive fields should be detected
	slog.Info("user", user) // want "struct 'User' contains sensitive fields and should not be logged entirely"

	// These should be fine
	slog.Info("name", user.Name)
	slog.Info("email", user.Email)
	slog.Info("safe", safeStruct)
}
