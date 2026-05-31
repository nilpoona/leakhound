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

// GetPasswordAndErr returns sensitive data at position 0 of a multi-value
// return. Cross-package callers that log position 0 must be flagged, while
// position 1 (error) must stay clean.
func GetPasswordAndErr(u User) (string, error) {
	return u.Password, nil
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

// DeepSink exercises a THREE-level transitive sink chain
// (DeepSink -> deepSink2 -> deepSink1 -> slog) so sink propagation must walk
// several edges of the local call graph before reaching the logging call.
func DeepSink(payload string) {
	deepSink2(payload)
}

func deepSink2(payload string) {
	deepSink1(payload)
}

func deepSink1(payload string) {
	slog.Info("payload", "v", payload)
}
