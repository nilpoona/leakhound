package config

import (
	"fmt"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	// defaultConfigFile is the default configuration file name
	defaultConfigFile = ".leakhound.yaml"

	// maxConfigSize is the maximum allowed configuration file size (1MB)
	maxConfigSize = 1 * 1024 * 1024

	// Configuration limits to prevent abuse
	maxTargets     = 20 // Maximum number of targets
	maxFunctions   = 50 // Maximum number of functions per target
	maxMethods     = 10 // Maximum number of method configs per target
	maxMethodNames = 50 // Maximum number of method names per method config
)

// Config represents the configuration file structure
type Config struct {
	Targets []TargetConfig `yaml:"targets"`
}

// TargetConfig represents a target logging library configuration
type TargetConfig struct {
	Package   string         `yaml:"package"`
	Functions []string       `yaml:"functions,omitempty"`
	Methods   []MethodConfig `yaml:"methods,omitempty"`
}

// MethodConfig represents a method configuration for a specific receiver type
type MethodConfig struct {
	Receiver string   `yaml:"receiver"`
	Names    []string `yaml:"names"`
}

var packagePathPattern = regexp.MustCompile(`^[a-z0-9.\-/]+$`)

// LoadConfig loads the configuration file from the specified path.
// If path is empty, it looks for the default configuration file in the current directory.
// Returns an empty Config if the file does not exist and no path was specified.
// Returns an empty Config and an error if loading or validation fails.
func LoadConfig(path string) (Config, error) {
	// If no path specified, try default file
	if path == "" {
		path = defaultConfigFile
		// Check if the default file exists
		if _, err := os.Stat(path); os.IsNotExist(err) {
			// Default file doesn't exist, return empty config (not an error)
			return Config{}, nil
		}
	}

	// Validate path to prevent path traversal for relative paths
	absPath, err := filepath.Abs(path)
	if err != nil {
		return Config{}, fmt.Errorf("failed to resolve config path: %w", err)
	}

	// Only check path traversal for relative paths
	if !filepath.IsAbs(path) {
		// Get current working directory
		wd, err := os.Getwd()
		if err != nil {
			return Config{}, fmt.Errorf("failed to get working directory: %w", err)
		}

		// Ensure the config file is within or relative to the working directory
		relPath, err := filepath.Rel(wd, absPath)
		if err != nil || strings.HasPrefix(relPath, "..") {
			return Config{}, fmt.Errorf("config file must be within the working directory: %s", path)
		}
	}

	// Check file size before reading
	fileInfo, err := os.Stat(absPath)
	if err != nil {
		return Config{}, fmt.Errorf("failed to stat config file: %w", err)
	}

	if fileInfo.Size() > maxConfigSize {
		return Config{}, fmt.Errorf("config file size (%d bytes) exceeds maximum allowed size (%d bytes)", fileInfo.Size(), maxConfigSize)
	}

	// Open and read the file
	file, err := os.Open(absPath)
	if err != nil {
		return Config{}, fmt.Errorf("failed to open config file: %w", err)
	}
	defer file.Close()

	// Limit the amount of data read
	limitedReader := io.LimitReader(file, maxConfigSize)

	// Parse YAML
	decoder := yaml.NewDecoder(limitedReader)
	decoder.KnownFields(true) // Reject unknown fields

	var config Config
	if err := decoder.Decode(&config); err != nil {
		return Config{}, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Validate the configuration
	if err := ValidateConfig(&config); err != nil {
		return Config{}, fmt.Errorf("invalid configuration: %w", err)
	}

	return config, nil
}

// ValidateConfig validates the configuration structure and content
func ValidateConfig(config *Config) error {
	if config == nil {
		return fmt.Errorf("config is nil")
	}

	// Check number of targets
	if len(config.Targets) > maxTargets {
		return fmt.Errorf("too many targets: %d (max: %d)", len(config.Targets), maxTargets)
	}

	// Validate each target
	for i, target := range config.Targets {
		if err := validateTarget(i, &target); err != nil {
			return err
		}
	}

	return nil
}

func validateTarget(index int, target *TargetConfig) error {
	// Validate package path
	if target.Package == "" {
		return fmt.Errorf("target[%d]: package path is required", index)
	}

	if err := validatePackagePath(target.Package); err != nil {
		return fmt.Errorf("target[%d]: %w", index, err)
	}

	// Check that at least one of functions or methods is specified
	if len(target.Functions) == 0 && len(target.Methods) == 0 {
		return fmt.Errorf("target[%d] (%s): at least one of 'functions' or 'methods' must be specified",
			index, target.Package)
	}

	// Check number of functions
	if len(target.Functions) > maxFunctions {
		return fmt.Errorf("target[%d] (%s): too many functions: %d (max: %d)",
			index, target.Package, len(target.Functions), maxFunctions)
	}

	// Validate each function name
	for _, fn := range target.Functions {
		if err := validateIdentifier(fn); err != nil {
			return fmt.Errorf("target[%d] (%s): invalid function name '%s': %w",
				index, target.Package, fn, err)
		}
	}

	// Check number of method configs
	if len(target.Methods) > maxMethods {
		return fmt.Errorf("target[%d] (%s): too many method configs: %d (max: %d)",
			index, target.Package, len(target.Methods), maxMethods)
	}

	// Validate each method config
	for j, method := range target.Methods {
		if err := validateMethodConfig(index, target.Package, j, &method); err != nil {
			return err
		}
	}

	return nil
}

func validateMethodConfig(targetIndex int, pkgPath string, methodIndex int, method *MethodConfig) error {
	// Validate receiver
	if method.Receiver == "" {
		return fmt.Errorf("target[%d] (%s), method[%d]: receiver is required",
			targetIndex, pkgPath, methodIndex)
	}

	if err := validateReceiver(method.Receiver); err != nil {
		return fmt.Errorf("target[%d] (%s), method[%d]: invalid receiver '%s': %w",
			targetIndex, pkgPath, methodIndex, method.Receiver, err)
	}

	// Check number of method names
	if len(method.Names) > maxMethodNames {
		return fmt.Errorf("target[%d] (%s), method[%d]: too many method names: %d (max: %d)",
			targetIndex, pkgPath, methodIndex, len(method.Names), maxMethodNames)
	}

	// Validate each method name
	for _, name := range method.Names {
		if err := validateIdentifier(name); err != nil {
			return fmt.Errorf("target[%d] (%s), method[%d]: invalid method name '%s': %w",
				targetIndex, pkgPath, methodIndex, name, err)
		}
	}

	return nil
}

// validatePackagePath validates that the package path contains only allowed characters
func validatePackagePath(pkg string) error {
	if !packagePathPattern.MatchString(pkg) {
		return fmt.Errorf("invalid package path: %s (must match pattern: %s)", pkg, packagePathPattern.String())
	}
	return nil
}

// validateIdentifier validates that the name is a valid Go identifier
func validateIdentifier(name string) error {
	if !token.IsIdentifier(name) {
		return fmt.Errorf("invalid identifier: %s", name)
	}
	return nil
}

// validateReceiver validates a receiver type specification (e.g., "*Logger", "Logger")
func validateReceiver(receiver string) error {
	// Remove optional pointer prefix
	name := strings.TrimPrefix(receiver, "*")

	if !token.IsIdentifier(name) {
		return fmt.Errorf("invalid receiver type: %s", receiver)
	}

	return nil
}
