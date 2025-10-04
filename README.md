
# leakhound 🐕

`leakhound` is a static analysis tool for Go that detects whether sensitive information is being accidentally logged.

Like a bloodhound sniffing out leaks, it tracks down potential data leakage risks in your code.

## Features

  - Detects if struct fields tagged with `sensitive:"true"` are being output by `log/slog`.
  - Integrates with `go vet`.
  - Can be used as a custom linter for `golangci-lint`.
  - Zero runtime overhead (static analysis only).
  - Can be run automatically in CI/CD pipelines.

## Installation

### As a CLI tool

```bash
go install github.com/yourname/leakhound@latest
```

### As a golangci-lint plugin

```bash
# Build the plugin
cd plugin
go build -buildmode=plugin -o leakhound.so

# Add to .golangci.yml
# (Details below)
```

## Usage

### 1. Tag sensitive fields

```go
package main

import "log/slog"

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

## Limitations

Due to the nature of static analysis, there are the following limitations:

### Cases that cannot be detected

```go
// ❌ When passed through a function
func logPassword(p string) {
    slog.Info("msg", "pass", p)
}
logPassword(user.Password) // Difficult to detect

// ❌ Via reflection
val := reflect.ValueOf(user).FieldByName("Password")
slog.Info("msg", "pass", val.Interface())

// ❌ Via an interface
var data interface{} = user.Password
slog.Info("msg", "pass", data)
```

### Cases that can be detected

```go
// ✅ Direct field access
slog.Info("msg", "pass", user.Password)

// ✅ When wrapped by slog.String, etc.
slog.Info("msg", slog.String("pass", user.Password))

// ✅ Via a pointer
userPtr := &user
slog.Info("msg", "pass", userPtr.Password)

// ✅ Entire struct containing sensitive fields
slog.Info("user data", user)                    // Detects if user has sensitive fields
slog.Info("user data", slog.Any("data", user))  // Also detects in nested function calls
```

## License

MIT License
