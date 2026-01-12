package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadConfig_ValidConfig(t *testing.T) {
	validYAML := `targets:
  - package: "go.uber.org/zap"
    functions:
      - "Info"
      - "Debug"
    methods:
      - receiver: "*Logger"
        names:
          - "Info"
          - "Debug"
`

	tmpFile := createTempConfigFile(t, validYAML)
	defer os.Remove(tmpFile)

	cfg, err := LoadConfig(tmpFile)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v, want nil", err)
	}

	if len(cfg.Targets) != 1 {
		t.Fatalf("len(cfg.Targets) = %d, want 1", len(cfg.Targets))
	}

	target := cfg.Targets[0]
	if target.Package != "go.uber.org/zap" {
		t.Errorf("target.Package = %s, want go.uber.org/zap", target.Package)
	}

	if len(target.Functions) != 2 {
		t.Errorf("len(target.Functions) = %d, want 2", len(target.Functions))
	}

	if len(target.Methods) != 1 {
		t.Errorf("len(target.Methods) = %d, want 1", len(target.Methods))
	}
}

func TestLoadConfig_EmptyPath_DefaultFileNotExists(t *testing.T) {
	// Create a temporary directory without the default config file
	tmpDir := t.TempDir()
	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(originalDir)

	if err := os.Chdir(tmpDir); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatalf("LoadConfig() error = %v, want nil", err)
	}

	if len(cfg.Targets) != 0 {
		t.Errorf("len(cfg.Targets) = %d, want 0 (empty config)", len(cfg.Targets))
	}
}

func TestLoadConfig_DefaultFile(t *testing.T) {
	tmpDir := t.TempDir()
	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(originalDir)

	if err := os.Chdir(tmpDir); err != nil {
		t.Fatal(err)
	}

	validYAML := `targets:
  - package: "github.com/rs/zerolog"
    methods:
      - receiver: "*Logger"
        names:
          - "Info"
`

	if err := os.WriteFile(defaultConfigFile, []byte(validYAML), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatalf("LoadConfig() error = %v, want nil", err)
	}

	if len(cfg.Targets) != 1 {
		t.Fatalf("len(cfg.Targets) = %d, want 1", len(cfg.Targets))
	}
}

func TestLoadConfig_FileNotExists(t *testing.T) {
	_, err := LoadConfig("/nonexistent/path/config.yaml")
	if err == nil {
		t.Error("LoadConfig() error = nil, want error")
	}
}

func TestLoadConfig_InvalidYAML(t *testing.T) {
	invalidYAML := `targets:
  - package: "go.uber.org/zap"
    functions:
      - "Info
  invalid yaml here
`

	tmpFile := createTempConfigFile(t, invalidYAML)
	defer os.Remove(tmpFile)

	_, err := LoadConfig(tmpFile)
	if err == nil {
		t.Error("LoadConfig() error = nil, want error for invalid YAML")
	}
}

func TestLoadConfig_UnknownFields(t *testing.T) {
	yamlWithUnknownFields := `targets:
  - package: "go.uber.org/zap"
    unknown_field: "value"
    functions:
      - "Info"
`

	tmpFile := createTempConfigFile(t, yamlWithUnknownFields)
	defer os.Remove(tmpFile)

	_, err := LoadConfig(tmpFile)
	if err == nil {
		t.Error("LoadConfig() error = nil, want error for unknown fields")
	}
}

func TestLoadConfig_ExceedsMaxSize(t *testing.T) {
	// Create a config file larger than maxConfigSize (1MB)
	tmpFile := filepath.Join(t.TempDir(), "large.yaml")
	file, err := os.Create(tmpFile)
	if err != nil {
		t.Fatal(err)
	}

	// Write more than 1MB of data
	largeContent := strings.Repeat("a", maxConfigSize+1)
	if _, err := file.WriteString(largeContent); err != nil {
		file.Close()
		t.Fatal(err)
	}
	file.Close()

	_, err = LoadConfig(tmpFile)
	if err == nil {
		t.Error("LoadConfig() error = nil, want error for file size exceeding limit")
	}
}

func TestLoadConfig_PathTraversal(t *testing.T) {
	tmpDir := t.TempDir()
	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(originalDir)

	if err := os.Chdir(tmpDir); err != nil {
		t.Fatal(err)
	}

	// Try to access a file outside the working directory
	_, err = LoadConfig("../../../etc/passwd")
	if err == nil {
		t.Error("LoadConfig() error = nil, want error for path traversal attempt")
	}
}

func TestValidateConfig_TooManyTargets(t *testing.T) {
	cfg := &Config{
		Targets: make([]TargetConfig, maxTargets+1),
	}

	err := ValidateConfig(cfg)
	if err == nil {
		t.Error("ValidateConfig() error = nil, want error for too many targets")
	}
}

func TestValidateConfig_InvalidPackagePath(t *testing.T) {
	cfg := &Config{
		Targets: []TargetConfig{
			{
				Package:   "INVALID/PATH",
				Functions: []string{"Info"},
			},
		},
	}

	err := ValidateConfig(cfg)
	if err == nil {
		t.Error("ValidateConfig() error = nil, want error for invalid package path")
	}
}

func TestValidateConfig_EmptyPackage(t *testing.T) {
	cfg := &Config{
		Targets: []TargetConfig{
			{
				Package:   "",
				Functions: []string{"Info"},
			},
		},
	}

	err := ValidateConfig(cfg)
	if err == nil {
		t.Error("ValidateConfig() error = nil, want error for empty package")
	}
}

func TestValidateConfig_NoFunctionsOrMethods(t *testing.T) {
	cfg := &Config{
		Targets: []TargetConfig{
			{
				Package: "go.uber.org/zap",
			},
		},
	}

	err := ValidateConfig(cfg)
	if err == nil {
		t.Error("ValidateConfig() error = nil, want error when both functions and methods are empty")
	}
}

func TestValidateConfig_TooManyFunctions(t *testing.T) {
	functions := make([]string, maxFunctions+1)
	for i := range functions {
		functions[i] = "Func"
	}

	cfg := &Config{
		Targets: []TargetConfig{
			{
				Package:   "go.uber.org/zap",
				Functions: functions,
			},
		},
	}

	err := ValidateConfig(cfg)
	if err == nil {
		t.Error("ValidateConfig() error = nil, want error for too many functions")
	}
}

func TestValidateConfig_InvalidFunctionName(t *testing.T) {
	cfg := &Config{
		Targets: []TargetConfig{
			{
				Package:   "go.uber.org/zap",
				Functions: []string{"Invalid-Name"},
			},
		},
	}

	err := ValidateConfig(cfg)
	if err == nil {
		t.Error("ValidateConfig() error = nil, want error for invalid function name")
	}
}

func TestValidateConfig_TooManyMethods(t *testing.T) {
	methods := make([]MethodConfig, maxMethods+1)
	for i := range methods {
		methods[i] = MethodConfig{
			Receiver: "*Logger",
			Names:    []string{"Info"},
		}
	}

	cfg := &Config{
		Targets: []TargetConfig{
			{
				Package: "go.uber.org/zap",
				Methods: methods,
			},
		},
	}

	err := ValidateConfig(cfg)
	if err == nil {
		t.Error("ValidateConfig() error = nil, want error for too many methods")
	}
}

func TestValidateConfig_EmptyReceiver(t *testing.T) {
	cfg := &Config{
		Targets: []TargetConfig{
			{
				Package: "go.uber.org/zap",
				Methods: []MethodConfig{
					{
						Receiver: "",
						Names:    []string{"Info"},
					},
				},
			},
		},
	}

	err := ValidateConfig(cfg)
	if err == nil {
		t.Error("ValidateConfig() error = nil, want error for empty receiver")
	}
}

func TestValidateConfig_InvalidReceiver(t *testing.T) {
	cfg := &Config{
		Targets: []TargetConfig{
			{
				Package: "go.uber.org/zap",
				Methods: []MethodConfig{
					{
						Receiver: "*Invalid-Receiver",
						Names:    []string{"Info"},
					},
				},
			},
		},
	}

	err := ValidateConfig(cfg)
	if err == nil {
		t.Error("ValidateConfig() error = nil, want error for invalid receiver")
	}
}

func TestValidateConfig_TooManyMethodNames(t *testing.T) {
	names := make([]string, maxMethodNames+1)
	for i := range names {
		names[i] = "Method"
	}

	cfg := &Config{
		Targets: []TargetConfig{
			{
				Package: "go.uber.org/zap",
				Methods: []MethodConfig{
					{
						Receiver: "*Logger",
						Names:    names,
					},
				},
			},
		},
	}

	err := ValidateConfig(cfg)
	if err == nil {
		t.Error("ValidateConfig() error = nil, want error for too many method names")
	}
}

func TestValidateConfig_InvalidMethodName(t *testing.T) {
	cfg := &Config{
		Targets: []TargetConfig{
			{
				Package: "go.uber.org/zap",
				Methods: []MethodConfig{
					{
						Receiver: "*Logger",
						Names:    []string{"Invalid-Method"},
					},
				},
			},
		},
	}

	err := ValidateConfig(cfg)
	if err == nil {
		t.Error("ValidateConfig() error = nil, want error for invalid method name")
	}
}

func TestValidateConfig_ValidPointerReceiver(t *testing.T) {
	cfg := &Config{
		Targets: []TargetConfig{
			{
				Package: "go.uber.org/zap",
				Methods: []MethodConfig{
					{
						Receiver: "*Logger",
						Names:    []string{"Info"},
					},
				},
			},
		},
	}

	err := ValidateConfig(cfg)
	if err != nil {
		t.Errorf("ValidateConfig() error = %v, want nil for valid pointer receiver", err)
	}
}

func TestValidateConfig_ValidValueReceiver(t *testing.T) {
	cfg := &Config{
		Targets: []TargetConfig{
			{
				Package: "go.uber.org/zap",
				Methods: []MethodConfig{
					{
						Receiver: "Logger",
						Names:    []string{"Info"},
					},
				},
			},
		},
	}

	err := ValidateConfig(cfg)
	if err != nil {
		t.Errorf("ValidateConfig() error = %v, want nil for valid value receiver", err)
	}
}

func TestValidatePackagePath(t *testing.T) {
	tests := []struct {
		name    string
		pkg     string
		wantErr bool
	}{
		{"valid standard lib", "log/slog", false},
		{"valid third party", "go.uber.org/zap", false},
		{"valid with dash", "github.com/rs/zerolog", false},
		{"valid with numbers", "github.com/user/lib2", false},
		{"invalid uppercase", "Go.Uber.Org/Zap", true},
		{"invalid space", "go.uber.org /zap", true},
		{"invalid special char", "go.uber.org/zap!", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePackagePath(tt.pkg)
			if (err != nil) != tt.wantErr {
				t.Errorf("validatePackagePath(%q) error = %v, wantErr %v", tt.pkg, err, tt.wantErr)
			}
		})
	}
}

func TestValidateIdentifier(t *testing.T) {
	tests := []struct {
		name    string
		ident   string
		wantErr bool
	}{
		{"valid simple", "Info", false},
		{"valid with underscore", "Debug_Log", false},
		{"valid with number", "Info2", false},
		{"invalid with dash", "Invalid-Name", true},
		{"invalid with space", "Invalid Name", true},
		{"invalid starting with number", "2Info", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateIdentifier(tt.ident)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateIdentifier(%q) error = %v, wantErr %v", tt.ident, err, tt.wantErr)
			}
		})
	}
}

func TestValidateReceiver(t *testing.T) {
	tests := []struct {
		name     string
		receiver string
		wantErr  bool
	}{
		{"valid pointer", "*Logger", false},
		{"valid value", "Logger", false},
		{"valid with underscore", "*Custom_Logger", false},
		{"invalid with dash", "*Invalid-Logger", true},
		{"invalid with space", "* Logger", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateReceiver(tt.receiver)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateReceiver(%q) error = %v, wantErr %v", tt.receiver, err, tt.wantErr)
			}
		})
	}
}

// Helper function to create a temporary config file
func createTempConfigFile(t *testing.T, content string) string {
	t.Helper()
	tmpFile := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(tmpFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return tmpFile
}
