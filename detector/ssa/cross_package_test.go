package ssa_test

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa/ssautil"

	leakhoundssa "github.com/nilpoona/leakhound/detector/ssa"
)

// TestCrossPackageSensitiveReturn tests LH0005 detection.
// A function in package A returns a sensitive value, and package B logs it.
func TestCrossPackageSensitiveReturn(t *testing.T) {
	tmpDir := t.TempDir()

	// Write go.mod for workspace
	goMod := filepath.Join(tmpDir, "go.mod")
	if err := os.WriteFile(goMod, []byte("module testpkg\n\ngo 1.21\n"), 0644); err != nil {
		t.Fatalf("Failed to write go.mod: %v", err)
	}

	// Package A: defines User and GetPassword function
	pkgADir := filepath.Join(tmpDir, "pkga")
	if err := os.MkdirAll(pkgADir, 0755); err != nil {
		t.Fatalf("Failed to create pkga dir: %v", err)
	}

	pkgAFile := filepath.Join(pkgADir, "a.go")
	pkgACode := `package pkga

type User struct {
	Name     string
	Password string ` + "`sensitive:\"true\"`" + `
}

// GetPassword returns the sensitive password field
func GetPassword(u User) string {
	return u.Password
}
`
	if err := os.WriteFile(pkgAFile, []byte(pkgACode), 0644); err != nil {
		t.Fatalf("Failed to write pkga/a.go: %v", err)
	}

	// Package B (main): imports pkga and logs the return value
	mainFile := filepath.Join(tmpDir, "main.go")
	mainCode := `package main

import (
	"log/slog"
	"testpkg/pkga"
)

func main() {
	user := pkga.User{Name: "alice", Password: "secret123"}
	password := pkga.GetPassword(user)  // Returns sensitive value
	slog.Info("user data", "pass", password)  // Should detect as LH0005
}
`
	if err := os.WriteFile(mainFile, []byte(mainCode), 0644); err != nil {
		t.Fatalf("Failed to write main.go: %v", err)
	}

	// Load all packages
	cfg := &packages.Config{
		Mode: packages.NeedName |
			packages.NeedFiles |
			packages.NeedCompiledGoFiles |
			packages.NeedImports |
			packages.NeedTypes |
			packages.NeedTypesSizes |
			packages.NeedSyntax |
			packages.NeedTypesInfo |
			packages.NeedDeps,
		Dir: tmpDir,
	}

	pkgs, err := packages.Load(cfg, "./...", ".")
	if err != nil {
		t.Fatalf("Failed to load packages: %v", err)
	}

	if len(pkgs) == 0 {
		t.Fatal("No packages loaded")
	}

	// Check for errors
	for _, pkg := range pkgs {
		if len(pkg.Errors) > 0 {
			for _, e := range pkg.Errors {
				t.Logf("Package %s error: %v", pkg.PkgPath, e)
			}
		}
	}

	// Build SSA
	prog, ssaPkgs := ssautil.AllPackages(pkgs, 0)
	prog.Build()

	if len(ssaPkgs) == 0 {
		t.Fatal("No SSA packages built")
	}

	// Analyze
	analyzer := leakhoundssa.NewSSAAnalyzer(prog, pkgs[0].Fset)
	analyzer.Analyze()

	findings := analyzer.GetFindings()

	// We expect 2 findings:
	// 1. LH0005 at the cross-package call site (pkga.GetPassword)
	// 2. sensitive-field at the log call site (slog.Info)
	if len(findings) != 2 {
		t.Errorf("Expected 2 findings, got %d", len(findings))
		for i, f := range findings {
			t.Logf("Finding %d: %s (rule: %s)", i, f.Message, f.RuleID)
		}
		return
	}

	// Check that we have both rule IDs
	ruleIDs := make(map[string]bool)
	for _, f := range findings {
		ruleIDs[f.RuleID] = true
		t.Logf("Found: rule=%s, message=%s", f.RuleID, f.Message)
	}

	if !ruleIDs["cross-pkg-sensitive-return"] {
		t.Error("Expected to find LH0005 (cross-pkg-sensitive-return)")
	}
	if !ruleIDs["sensitive-field"] {
		t.Error("Expected to find sensitive-field at log call")
	}

	t.Log("✅ Successfully detected cross-package sensitive return with LH0005!")
}

// TestCrossPackageSensitiveSink tests LH0006 detection.
// A function in package A has a parameter that is logged inside the function.
// Package B passes a sensitive value to that parameter.
func TestCrossPackageSensitiveSink(t *testing.T) {
	tmpDir := t.TempDir()

	// Write go.mod for workspace
	goMod := filepath.Join(tmpDir, "go.mod")
	if err := os.WriteFile(goMod, []byte("module testpkg\n\ngo 1.21\n"), 0644); err != nil {
		t.Fatalf("Failed to write go.mod: %v", err)
	}

	// Package A: defines LogIt function that logs its parameter
	pkgADir := filepath.Join(tmpDir, "pkga")
	if err := os.MkdirAll(pkgADir, 0755); err != nil {
		t.Fatalf("Failed to create pkga dir: %v", err)
	}

	pkgAFile := filepath.Join(pkgADir, "a.go")
	pkgACode := `package pkga

import "log"

// LogIt logs the payload parameter
func LogIt(payload string) {
	log.Println(payload)
}
`
	if err := os.WriteFile(pkgAFile, []byte(pkgACode), 0644); err != nil {
		t.Fatalf("Failed to write pkga/a.go: %v", err)
	}

	// Package B (main): imports pkga and passes sensitive value
	mainFile := filepath.Join(tmpDir, "main.go")
	mainCode := `package main

import "testpkg/pkga"

type User struct {
	Name     string
	Password string ` + "`sensitive:\"true\"`" + `
}

func main() {
	user := User{Name: "alice", Password: "secret123"}
	pkga.LogIt(user.Password)  // Should detect as LH0006
}
`
	if err := os.WriteFile(mainFile, []byte(mainCode), 0644); err != nil {
		t.Fatalf("Failed to write main.go: %v", err)
	}

	// Load all packages
	cfg := &packages.Config{
		Mode: packages.NeedName |
			packages.NeedFiles |
			packages.NeedCompiledGoFiles |
			packages.NeedImports |
			packages.NeedTypes |
			packages.NeedTypesSizes |
			packages.NeedSyntax |
			packages.NeedTypesInfo |
			packages.NeedDeps,
		Dir: tmpDir,
	}

	pkgs, err := packages.Load(cfg, "./...", ".")
	if err != nil {
		t.Fatalf("Failed to load packages: %v", err)
	}

	if len(pkgs) == 0 {
		t.Fatal("No packages loaded")
	}

	// Check for errors
	for _, pkg := range pkgs {
		if len(pkg.Errors) > 0 {
			for _, e := range pkg.Errors {
				t.Logf("Package %s error: %v", pkg.PkgPath, e)
			}
		}
	}

	// Build SSA
	prog, ssaPkgs := ssautil.AllPackages(pkgs, 0)
	prog.Build()

	if len(ssaPkgs) == 0 {
		t.Fatal("No SSA packages built")
	}

	// Analyze
	analyzer := leakhoundssa.NewSSAAnalyzer(prog, pkgs[0].Fset)
	analyzer.Analyze()

	findings := analyzer.GetFindings()

	// We expect at least 1 finding with rule ID "cross-pkg-sensitive-sink" (LH0006)
	// Note: There may also be a sensitive-field finding inside pkga.LogIt
	if len(findings) == 0 {
		t.Error("Expected at least 1 finding, got 0")
		return
	}

	// Check for LH0006
	hasLH0006 := false
	for _, f := range findings {
		t.Logf("Found: rule=%s, message=%s", f.RuleID, f.Message)
		if f.RuleID == "cross-pkg-sensitive-sink" {
			hasLH0006 = true
		}
	}

	if !hasLH0006 {
		t.Error("Expected to find LH0006 (cross-pkg-sensitive-sink)")
	} else {
		t.Log("✅ Successfully detected cross-package sensitive sink with LH0006!")
	}
}
