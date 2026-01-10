package customlogger

type User struct {
	Name     string
	Password string `sensitive:"true"`
}

func ExampleWithConfig(logger *CustomLogger, user User) {
	// Should be detected when config is loaded
	logger.Info("user login", user.Password) // want "sensitive field 'User.Password' should not be logged"

	// Should be detected via variable tracking
	password := user.Password
	logger.Debug("debug", password) // want "variable \"password\" contains sensitive field \"User.Password\""

	// Should be detected: entire struct
	logger.Error("error", user) // want "struct 'User' contains sensitive fields and should not be logged entirely"
}

