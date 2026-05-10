package main

import (
	"log/slog"
)

type User struct {
	Name     string
	Password string `sensitive:"true"`
}

func main() {
	user := User{
		Name:     "alice",
		Password: "secret123",
	}

	// Test slog.Group with sensitive field inside
	slog.Info("user info",
		slog.Group("user",
			"name", user.Name,
			"password", user.Password, // want "sensitive field 'User.Password' should not be logged"
		),
	)

	// Test nested slog.Group with sensitive field
	slog.Info("nested group",
		slog.Group("outer",
			slog.Group("inner",
				"password", user.Password, // want "sensitive field 'User.Password' should not be logged"
			),
		),
	)

	// Test slog.Group with entire struct
	slog.Info("group with struct",
		slog.Group("data",
			"user", user, // want "struct 'User' contains sensitive fields and should not be logged entirely"
		),
	)

	// Safe case - no sensitive data
	slog.Info("safe group",
		slog.Group("safe",
			"name", user.Name,
		),
	)

	// Test variable tracking in slog.Group
	password := user.Password
	slog.Info("variable in group",
		slog.Group("credentials",
			"pass", password, // want "sensitive variable 'password' contains data from 'User.Password' and should not be logged"
		),
	)

	// Test function return value in slog.Group
	slog.Info("function return in group",
		slog.Group("auth",
			"secret", getPassword(user), // want "sensitive function call 'getPassword' returns data from 'User.Password' and should not be logged"
		),
	)

	// Test sensitive data passed as parameter to function that logs it
	doSomething(user.Password, user.Name)

	// Test sensitive data passed as parameter to function that logs in slog.Group
	logInGroup(user.Password, user.Name)
}

func getPassword(u User) string {
	return u.Password
}

func doSomething(a, b string) {
	// a is sensitive data passed from caller
	slog.Info("message", "value", a) // want "sensitive parameter 'a' contains data from 'User.Password' and should not be logged"
}

func logInGroup(secret, name string) {
	// secret is sensitive data passed from caller
	// name is NOT sensitive (this verifies the parameter mapping bug fix)
	slog.Info("grouped data",
		slog.Group("info",
			"secret", secret, // want "variable \"secret\" contains sensitive field \"User.Password\""
			"name", name, // name should NOT be flagged (bug fix verification)
		),
	)
}
