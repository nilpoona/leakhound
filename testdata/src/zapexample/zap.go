package zapexample

import "go.uber.org/zap"

type User struct {
	Name     string
	Password string `sensitive:"true"`
	APIKey   string `sensitive:"true"`
}

func ExampleZapLogger(logger *zap.Logger, user User) {
	// Should be detected: passing sensitive field to logger method
	logger.Info("user login", zap.String("password", user.Password)) // want "sensitive field 'Password' is being logged"

	// Should be detected: passing sensitive field via variable
	password := user.Password
	logger.Debug("debug info", zap.String("pwd", password)) // want "sensitive variable 'password' containing field 'Password' is being logged"

	// Should NOT be detected: safe field
	logger.Info("user info", zap.String("name", user.Name))

	// Should be detected: entire struct with sensitive field
	logger.Error("user error", zap.Any("user", user)) // want "struct 'User' with sensitive fields is being logged"
}

func ExampleZapSugar(logger *zap.SugaredLogger, user User) {
	// Should be detected
	logger.Infow("user data", "password", user.Password) // want "sensitive field 'Password' is being logged"

	// Should be detected
	apiKey := user.APIKey
	logger.Debugw("api call", "key", apiKey) // want "sensitive variable 'apiKey' containing field 'APIKey' is being logged"
}
