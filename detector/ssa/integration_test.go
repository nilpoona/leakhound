package ssa_test

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa/ssautil"

	leakhoundssa "github.com/nilpoona/leakhound/detector/ssa"
)

// TestMinimalDirectFieldAccess tests the most basic case:
// Detecting direct field access in a logging call.
//
// This is our first integration test to validate the entire SSA pipeline:
// 1. Load Go package with packages.Load
// 2. Build SSA program with ssautil
// 3. Analyze with SSAAnalyzer
// 4. Detect sensitive field access in slog.Info call
func TestMinimalDirectFieldAccess(t *testing.T) {
	// Create a temporary directory for our test package
	tmpDir := t.TempDir()

	// Write go.mod file
	goMod := filepath.Join(tmpDir, "go.mod")
	goModContent := `module testpkg

go 1.21
`
	if err := os.WriteFile(goMod, []byte(goModContent), 0644); err != nil {
		t.Fatalf("Failed to write go.mod: %v", err)
	}

	// Write the minimal test case
	testFile := filepath.Join(tmpDir, "main.go")
	code := `package main

import "log/slog"

type User struct {
	Name     string
	Password string ` + "`sensitive:\"true\"`" + `
}

func main() {
	user := User{Name: "alice", Password: "secret123"}
	slog.Info("user data", "pass", user.Password)
}
`
	if err := os.WriteFile(testFile, []byte(code), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Step 1: Load the package with type information
	cfg := &packages.Config{
		Mode: packages.NeedName |
			packages.NeedFiles |
			packages.NeedCompiledGoFiles |
			packages.NeedImports |
			packages.NeedTypes |
			packages.NeedTypesSizes |
			packages.NeedSyntax |
			packages.NeedTypesInfo,
		Dir: tmpDir,
	}

	pkgs, err := packages.Load(cfg, ".")
	if err != nil {
		t.Fatalf("Failed to load package: %v", err)
	}

	if len(pkgs) == 0 {
		t.Fatalf("No packages loaded (error: %v)", err)
	}

	// Check for package errors
	for _, pkg := range pkgs {
		if len(pkg.Errors) > 0 {
			for _, e := range pkg.Errors {
				t.Logf("Package error: %v", e)
			}
		}
	}

	if len(pkgs[0].Errors) > 0 {
		t.Fatalf("Package has errors: %v", pkgs[0].Errors)
	}

	// Step 2: Build SSA program
	prog, ssaPkgs := ssautil.AllPackages(pkgs, 0)
	prog.Build()

	if len(ssaPkgs) == 0 {
		t.Fatal("No SSA packages built")
	}

	// Step 3: Create and run SSA analyzer
	analyzer := leakhoundssa.NewSSAAnalyzer(prog, pkgs[0].Fset)
	analyzer.Analyze()

	// Step 4: Verify detection
	findings := analyzer.GetFindings()

	if len(findings) != 1 {
		t.Errorf("Expected 1 finding, got %d", len(findings))
		for i, f := range findings {
			t.Logf("Finding %d: %s (rule: %s)", i, f.Message, f.RuleID)
		}
		return
	}

	finding := findings[0]
	if finding.RuleID != "sensitive-field" {
		t.Errorf("Expected rule ID 'sensitive-field', got %q", finding.RuleID)
	}

	expectedMsg := "sensitive field \"User.Password\" is logged and should not be logged"
	if finding.Message != expectedMsg {
		t.Errorf("Expected message %q, got %q", expectedMsg, finding.Message)
	}

	if finding.Source == nil {
		t.Error("Expected finding to have source information")
	} else {
		if finding.Source.FieldName != "Password" {
			t.Errorf("Expected field name 'Password', got %q", finding.Source.FieldName)
		}
		if finding.Source.TypeName != "User" {
			t.Errorf("Expected type name 'User', got %q", finding.Source.TypeName)
		}
	}

	t.Log("✅ Successfully detected sensitive field in slog.Info call!")
}
