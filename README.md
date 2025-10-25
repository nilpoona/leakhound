
# leakhound 🐕
`leakhound` is a static analysis tool for Go that detects whether sensitive information is being accidentally logged.
Like a bloodhound sniffing out leaks, it tracks down potential data leakage risks in your code.

## Features
  - Detects if struct fields tagged with `sensitive:"true"` are being output by logging functions.
  - Supports multiple logging packages: `log/slog` and `fmt`.
  - Zero runtime overhead (static analysis only).
  - Can be run automatically in CI/CD pipelines.

## Installation
### As a CLI tool
```bash
go install github.com/nilpoona/leakhound@latest
```

## Usage
### 1. Tag sensitive fields
```go
package main

import (
    "fmt"
    "log/slog"
)

type User struct {
    ID       int
    Name     string
    Password string `sensitive:"true" json:"-"`
    APIKey   string `sensitive:"true" json:"-"`
    Email    string `sensitive:"true" json:"email"`
}

type Config struct {
    Host     string
    Port     int
    Token    string `sensitive:"true"`
    Database string
}
```

### 2. Run static analysis
#### Run as a CLI tool
```bash
# Inspect the current directory
leakhound ./...

# Inspect a specific package
leakhound ./internal/...
```

## Design Philosophy
### Why static analysis?
`leakhound` uses **static analysis** rather than **runtime masking**.

#### Advantages of Static Analysis
  - ✅ **Preventative**: Find issues at the code review stage.
  - ✅ **Zero runtime cost**: No performance impact during execution.
  - ✅ **Reliable prevention**: Blocks sensitive data before it can be logged.

## Supported Logging Libraries
Currently supported logging libraries:
  - ✅ `log/slog` (Go 1.21+)
  - ✅ Custom loggers with slog-compatible method signatures
  - ✅ `fmt` (Printf, Println, Print, etc.)

## Limitations
Due to the nature of static analysis, there are the following limitations:

### Cases that cannot be detected
```go
// ❌ When passed through a function
func logPassword(p string) {
    slog.Info("msg", "pass", p)
    fmt.Println("pass:", p)
}
logPassword(user.Password) // Difficult to detect

// ❌ Via reflection
val := reflect.ValueOf(user).FieldByName("Password")
slog.Info("msg", "pass", val.Interface())
fmt.Println(val.Interface())

// ❌ Via an interface
var data interface{} = user.Password
slog.Info("msg", "pass", data)
fmt.Println(data)
```

### Cases that can be detected

#### slog package (including custom loggers)
```go
// ✅ Direct field access
slog.Info("msg", "pass", user.Password)
logger.Info("msg", "pass", user.Password)  // Custom logger with Info method

// ✅ When wrapped by slog.String, etc.
slog.Info("msg", slog.String("pass", user.Password))

// ✅ Via a pointer
userPtr := &user
slog.Info("msg", "pass", userPtr.Password)

// ✅ Entire struct containing sensitive fields
slog.Info("user data", user)                    // Detects if user has sensitive fields
slog.Info("user data", slog.Any("data", user))  // Also detects in nested function calls
logger.Error("config", config)                  // Custom logger detects struct with sensitive fields

// ✅ All slog-style method signatures (custom loggers too)
logger.Debug("msg", "secret", user.Password)
logger.Error("msg", "secret", user.Password)
logger.Warn("msg", "secret", user.Password)
logger.InfoContext(ctx, "msg", "secret", user.Password)
logger.ErrorContext(ctx, "msg", "secret", user.Password)
logger.WarnContext(ctx, "msg", "secret", user.Password)
logger.DebugContext(ctx, "msg", "secret", user.Password)
logger.Log(ctx, slog.LevelInfo, "msg", "secret", user.Password)
logger.LogAttrs(ctx, slog.LevelInfo, "msg", slog.String("pass", user.Password))
```

#### fmt package
```go
// ✅ Direct field access
fmt.Println(user.Password)
fmt.Printf("password: %s", user.Password)
fmt.Print("token:", config.Token)

// ✅ Via a pointer
userPtr := &user
fmt.Println(userPtr.Password)

// ✅ Entire struct containing sensitive fields
fmt.Println(user)           // Detects if user has sensitive fields
fmt.Printf("%+v", user)     // Detects with format verbs
fmt.Printf("%#v", config)   // Detects with any format

// ✅ Multiple arguments
fmt.Println("User:", user.Name, "Pass:", user.Password)  // Detects Password
```

## Example Detection Output
```bash
$ leakhound ./...
./main.go:15:2: sensitive field "Password" should not be logged
./main.go:18:2: sensitive field "APIKey" should not be logged
./config.go:23:12: sensitive field "Token" should not be logged
./user.go:10:14: struct "User" contains sensitive fields and should not be logged
```

## License
MIT License