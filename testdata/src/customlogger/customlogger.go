package customlogger

// CustomLogger is a simple custom logger for testing config-based detection
type CustomLogger struct{}

func (l *CustomLogger) Log(args ...interface{}) {}
func (l *CustomLogger) Logf(format string, args ...interface{}) {}
func (l *CustomLogger) Info(args ...interface{}) {}
func (l *CustomLogger) Debug(args ...interface{}) {}
func (l *CustomLogger) Error(args ...interface{}) {}

// Package-level functions
func Log(args ...interface{}) {}
func Logf(format string, args ...interface{}) {}
