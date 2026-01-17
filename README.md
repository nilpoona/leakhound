
# leakhound 🐕

A Go static analysis tool that detects accidental logging 
of sensitive struct fields tagged with `sensitive:"true"`, preventing 
data leaks in logs.

## Badges
![Build Status](https://github.com/nilpoona/leakhound/workflows/CI/badge.svg)
[![License](https://img.shields.io/github/license/nilpoona/leakhound)](/LICENSE)
[![Release](https://img.shields.io/github/release/nilpoona/leakhound.svg)](https://github.com/nilpoona/leakhound/releases/latest)
[![Go Report Card](https://goreportcard.com/badge/github.com/nilpoona/leakhound)](https://goreportcard.com/report/github.com/nilpoona/leakhound)

## Features
  - **Data Flow Analysis**: Tracks sensitive data through variables, function parameters, and return values
  - Detects if struct fields tagged with `sensitive:"true"` are being output by logging functions
  - Supports multiple logging packages: `log/slog`, `log`, and `fmt`
  - **Configurable**: Add support for third-party logging libraries (zap, zerolog, logrus, etc.) via YAML configuration
  - Zero runtime overhead (static analysis only)

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

#### Output Formats
`leakhound` supports multiple output formats for different use cases:

**Text format (default)**
```bash
# Human-readable output to stderr
leakhound ./...
```
This format is compatible with existing tooling and outputs findings in the standard format: `/path/to/file.go:line:col: message`

**SARIF format (v2.1.0)**
```bash
# Machine-readable JSON output to stdout
leakhound --format=sarif ./...

# Save SARIF output to file
leakhound --format=sarif ./... > results.sarif
```
SARIF (Static Analysis Results Interchange Format) is an industry-standard format for static analysis results. It integrates with:
- GitHub Advanced Security (Code Scanning)
- Visual Studio Code
- Azure DevOps
- GitLab
- Other CI/CD platforms

The SARIF output includes:
- Rule metadata with severity levels
- Precise source locations (file path, line, column)
- Detailed descriptions for each finding
- Tool version information

### 3. Nested struct support
`leakhound` can also detect sensitive fields in nested/embedded structs:

```go
type Config struct {
    Secret string `sensitive:"true"`
}

type WrapConfig struct {
    Config  // Embedded struct with sensitive field
    Description string
}

wrapConfig := WrapConfig{...}

// ✅ Both cases will be detected
slog.Info("wrapConfig", wrapConfig)              // Detects embedded sensitive fields
slog.Info("secret", wrapConfig.Config.Secret)    // Detects nested field access
```

## Design Philosophy
### Why static analysis?
`leakhound` uses **static analysis** rather than **runtime masking**.

#### Advantages of Static Analysis
  - ✅ **Preventative**: Find issues at the code review stage.
  - ✅ **Zero runtime cost**: No performance impact during execution.
  - ✅ **Reliable prevention**: Blocks sensitive data before it can be logged.

## Supported Logging Libraries

### Built-in Support (No Configuration Required)
  - ✅ `log/slog` (Go 1.21+)
  - ✅ `*slog.Logger` type custom loggers
  - ✅ `log` (standard log package)
  - ✅ `*log.Logger` type custom loggers
  - ✅ `fmt` (Printf, Println, Print, etc.)

### Third-party Libraries (via Configuration)
  - ✅ `go.uber.org/zap` ([example config](examples/zap.yaml))
  - ✅ `github.com/rs/zerolog` ([example config](examples/zerolog.yaml))
  - ✅ `github.com/sirupsen/logrus` ([example config](examples/logrus.yaml))
  - ✅ Any custom logging library

## Configuration

### Quick Start

For standard libraries (`log`, `log/slog`, `fmt`), no configuration is needed. Just run:

```bash
leakhound ./...
```

### Adding Third-party Logger Support

To detect sensitive data in third-party logging libraries like zap, zerolog, or logrus:
Note: The provided configuration files only cover commonly used methods for each library. They do not cover all methods, so please customize them as needed.

1. **Download a pre-made configuration**:

```bash
# For zap
curl -o .leakhound.yaml https://raw.githubusercontent.com/nilpoona/leakhound/main/examples/zap.yaml

# For zerolog
curl -o .leakhound.yaml https://raw.githubusercontent.com/nilpoona/leakhound/main/examples/zerolog.yaml

# For logrus
curl -o .leakhound.yaml https://raw.githubusercontent.com/nilpoona/leakhound/main/examples/logrus.yaml
```


2. **Run leakhound**:

```bash
leakhound ./...
```

The tool will automatically find `.leakhound.yaml` in the current directory.

### Custom Configuration

Create a `.leakhound.yaml` file in your project root:

```yaml
targets:
  - package: "go.uber.org/zap"
    methods:
      - receiver: "*Logger"
        names:
          - "Info"
          - "Debug"
          - "Error"
      - receiver: "*SugaredLogger"
        names:
          - "Infow"
          - "Debugw"
```

Or specify a custom path:

```bash
leakhound --config path/to/config.yaml ./...
```

### Configuration Format

```yaml
targets:
  - package: "go.uber.org/zap"           # Package import path
    functions:                            # Package-level functions (optional)
      - "Info"
      - "Debug"
    methods:                              # Methods on specific types (optional)
      - receiver: "*Logger"               # Receiver type (* for pointer)
        names:                            # Method names
          - "Info"
          - "Debug"
```

**Requirements**:
- At least one of `functions` or `methods` must be specified
- Package paths must be lowercase: `a-z`, `0-9`, `.`, `-`, `/`
- Function and method names must be valid Go identifiers
- Receiver types can be pointer (`*Logger`) or value (`Logger`)

**Limits** (to prevent abuse):
- Maximum 20 targets
- Maximum 50 functions per target
- Maximum 10 method configs per target
- Maximum 50 method names per method config

See [examples/](examples/) for more configuration examples.

## Advanced Detection: Data Flow Tracking

### Variable Assignments
```go
// ✅ Variable assignment tracking
password := user.Password
slog.Info("msg", "pass", password)  // Detected!
log.Println("password:", password)  // Detected!
fmt.Printf("secret: %s", password)  // Detected!
```

### Function Parameters (same package)
```go
// ✅ Function parameter tracking
func logValue(val string) {
    slog.Info("msg", val)  // Detected!
}

password := user.Password
logValue(password)  // Tracks sensitive data through function call
```

### Nested Function Calls
```go
// ✅ Nested function call tracking 
func inner(data string) {
    log.Println(data)  // Detected!
}

func outer(val string) {
    inner(val)  // Tracks through multiple levels
}

password := user.Password
outer(password)  // Tracks up to 5 levels deep
```

### Return Values
```go
// ✅ Return value tracking
func getPassword(user User) string {
    return user.Password
}

// Direct use
slog.Info("msg", getPassword(user))  // Detected!

// Via variable
password := getPassword(user)
log.Println(password)  // Detected!
```

## Limitations
Due to the nature of static analysis, there are the following limitations:

### Cases that cannot be detected
```go
// ❌ Cross-package function calls (out of scope)
import "github.com/external/pkg"
password := user.Password
pkg.ProcessData(password)  // Not tracked

// ❌ Variadic arguments (out of scope)
func logMultiple(vals ...string) {
    for _, v := range vals {
        slog.Info("msg", v)
    }
}
password := user.Password
logMultiple("safe", password)  // Not tracked

// ❌ Multiple return values (not yet implemented)
func getCredentials(user User) (string, string, error) {
    return user.Name, user.Password, nil
}
name, password, err := getCredentials(user)
slog.Info("msg", password)  // Position tracking not implemented

// ❌ Via reflection
val := reflect.ValueOf(user).FieldByName("Password")
slog.Info("msg", "pass", val.Interface())

// ❌ Via an interface
var data interface{} = user.Password
slog.Info("msg", "pass", data)
```

### Cases that can be detected

#### slog package (including *slog.Logger type)
```go
// ✅ Direct field access
slog.Info("msg", "pass", user.Password)
logger.Info("msg", "pass", user.Password)  // logger is *slog.Logger

// ✅ Variable assignments
password := user.Password
slog.Info("msg", "pass", password)  // Tracked!
logger.Error("msg", "pass", password)  // Tracked!

// ✅ When wrapped by slog.String, etc.
slog.Info("msg", slog.String("pass", user.Password))

// ✅ Via a pointer
userPtr := &user
slog.Info("msg", "pass", userPtr.Password)

// ✅ Entire struct containing sensitive fields
slog.Info("user data", user)                    // Detects if user has sensitive fields
slog.Info("user data", slog.Any("data", user))  // Also detects in nested function calls
logger.Error("config", config)                  // *slog.Logger detects struct with sensitive fields

// ✅ All *slog.Logger methods
logger.Debug("msg", "secret", user.Password)
logger.Error("msg", "secret", user.Password)
logger.Warn("msg", "secret", user.Password)
logger.InfoContext(ctx, "msg", "secret", user.Password)
logger.ErrorContext(ctx, "msg", "secret", user.Password)
logger.WarnContext(ctx, "msg", "secret", user.Password)
logger.DebugContext(ctx, "msg", "secret", user.Password)
logger.Log(ctx, slog.LevelInfo, "msg", "secret", user.Password)
logger.LogAttrs(ctx, slog.LevelInfo, "msg", slog.String("pass", user.Password))

// ✅ With method chaining (edge case)
logger.With("key", "val").Info("config", config)  // Detects even after With()

// ✅ Nested/embedded structs with sensitive fields
type WrapConfig struct {
    Config  // Embedded struct with sensitive field
}
wrapConfig := WrapConfig{...}
slog.Info("wrapConfig", wrapConfig)              // Detects embedded sensitive fields
slog.Info("secret", wrapConfig.Config.Secret)    // Detects nested field access
```

#### log package (including *log.Logger type)
```go
// ✅ Direct field access
log.Print("secret:", user.Password)
log.Printf("secret: %s", user.Password)
log.Println("secret:", user.Password)
customLogger.Print("token:", config.Token)  // customLogger is *log.Logger

// ✅ Variable assignments
p := user.Password
log.Println("password:", p)  // Tracked!
customLogger.Print("token:", p)  // Tracked!

// ✅ All log package functions
log.Fatal("secret:", user.Password)
log.Fatalf("secret: %s", user.Password)
log.Fatalln("secret:", user.Password)
log.Panic("secret:", user.Password)
log.Panicf("secret: %s", user.Password)
log.Panicln("secret:", user.Password)

// ✅ Entire struct containing sensitive fields
log.Print("config:", config)              // Detects if config has sensitive fields
log.Printf("config: %+v", config)         // Detects with format verbs
customLogger.Println("user:", user)       // *log.Logger detects struct with sensitive fields

// ✅ All *log.Logger methods
customLogger.Fatal("secret:", user.Password)
customLogger.Fatalf("secret: %s", user.Password)
customLogger.Fatalln("secret:", user.Password)
customLogger.Panic("secret:", user.Password)
customLogger.Panicf("secret: %s", user.Password)
customLogger.Panicln("secret:", user.Password)
customLogger.Output(2, user.Password)

// ✅ Nested/embedded structs with sensitive fields
type WrapConfig struct {
    Config  // Embedded struct with sensitive field
}
wrapConfig := WrapConfig{...}
log.Print("wrapConfig:", wrapConfig)             // Detects embedded sensitive fields
log.Println("secret:", wrapConfig.Config.Secret) // Detects nested field access
```

#### fmt package
```go
// ✅ Direct field access
fmt.Println(user.Password)
fmt.Printf("password: %s", user.Password)
fmt.Print("token:", config.Token)

// ✅ Variable assignments
secret := config.APIKey
fmt.Printf("key: %s", secret)  // Tracked!

// ✅ Via a pointer
userPtr := &user
fmt.Println(userPtr.Password)

// ✅ Entire struct containing sensitive fields
fmt.Println(user)           // Detects if user has sensitive fields
fmt.Printf("%+v", user)     // Detects with format verbs
fmt.Printf("%#v", config)   // Detects with any format

// ✅ Multiple arguments
fmt.Println("User:", user.Name, "Pass:", user.Password)  // Detects Password

// ✅ Nested/embedded structs with sensitive fields
type WrapConfig struct {
    Config  // Embedded struct with sensitive field
}
wrapConfig := WrapConfig{...}
fmt.Println("wrapConfig:", wrapConfig)             // Detects embedded sensitive fields
fmt.Printf("secret: %s", wrapConfig.Config.Secret) // Detects nested field access
```

## Example Detection Output
```bash
$ leakhound ./...
./main.go:15:2: sensitive field 'User.Password' should not be logged (tagged with sensitive:"true")
./main.go:18:27: variable "password" contains sensitive field "User.Password" (tagged with sensitive:"true")
./main.go:23:19: variable "val" contains sensitive field "User.Password" (tagged with sensitive:"true")
./config.go:34:19: function call returns sensitive field "Config.APIKey" (tagged with sensitive:"true")
./user.go:10:14: struct 'User' contains sensitive fields and should not be logged entirely
```
