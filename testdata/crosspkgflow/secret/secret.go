package secret

import "log/slog"

// User has a sensitive Password field, declared in a separate package
// so callers in other packages must rely on cross-package tracking.
type User struct {
	Name     string
	Password string `sensitive:"true"`
}

// GetPassword returns sensitive data. Any caller in another package that
// logs the return value must be flagged with LH0005.
func GetPassword(u User) string {
	return u.Password
}

// LogIt forwards its parameter to a logging function. Any caller in another
// package that passes a sensitive value here must be flagged with LH0006 at
// the call site.
func LogIt(payload string) {
	slog.Info("payload", "v", payload)
}

// Indirect mirrors LogIt but routes through one more level of cross-package
// indirection inside this package so the sink propagation must walk through
// the local call graph too.
func Indirect(payload string) {
	LogIt(payload)
}
