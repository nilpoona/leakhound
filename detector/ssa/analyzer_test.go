package ssa

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"testing"

	"golang.org/x/tools/go/ssa"
)

// TestBasicFieldAccess tests SSA-based detection of direct field access.
func TestBasicFieldAccess(t *testing.T) {
	src := `
package main

import "log/slog"

type User struct {
	Name     string
	Password string ` + "`sensitive:\"true\"`" + `
}

func main() {
	user := User{Name: "alice", Password: "secret123"}
	slog.Info("user", "pass", user.Password)
}
`

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "test.go", src, 0)
	if err != nil {
		t.Fatalf("Failed to parse source: %v", err)
	}

	// Create types package
	pkg := types.NewPackage("main", "")
	conf := types.Config{Importer: nil}
	info := &types.Info{
		Types:      make(map[ast.Expr]types.TypeAndValue),
		Defs:       make(map[*ast.Ident]types.Object),
		Uses:       make(map[*ast.Ident]types.Object),
		Implicits:  make(map[ast.Node]types.Object),
		Selections: make(map[*ast.SelectorExpr]*types.Selection),
		Scopes:     make(map[ast.Node]*types.Scope),
	}

	// TODO: This test needs proper setup with SSA construction
	// For now, we're validating the package structure compiles
	_, _ = conf, info
	_, _ = pkg, file

	t.Skip("SSA construction requires full package loading - will implement in next phase")
}

// TestSensitiveFieldDetection tests that sensitive fields are correctly identified.
func TestSensitiveFieldDetection(t *testing.T) {
	tests := []struct {
		name     string
		tag      string
		expected bool
	}{
		{
			name:     "sensitive true",
			tag:      `sensitive:"true"`,
			expected: true,
		},
		{
			name:     "sensitive false",
			tag:      `sensitive:"false"`,
			expected: false,
		},
		{
			name:     "no tag",
			tag:      `json:"password"`,
			expected: false,
		},
		{
			name:     "empty tag",
			tag:      "",
			expected: false,
		},
		{
			name:     "multiple tags with sensitive",
			tag:      `json:"password" sensitive:"true" db:"pwd"`,
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasSensitiveTag(tt.tag)
			if got != tt.expected {
				t.Errorf("hasSensitiveTag(%q) = %v, want %v", tt.tag, got, tt.expected)
			}
		})
	}
}

// TestSSAAnalyzerCreation tests that the analyzer can be created.
func TestSSAAnalyzerCreation(t *testing.T) {
	fset := token.NewFileSet()
	prog := ssa.NewProgram(fset, ssa.SanityCheckFunctions)

	analyzer := NewSSAAnalyzer(prog, fset)
	if analyzer == nil {
		t.Fatal("NewSSAAnalyzer returned nil")
	}

	if analyzer.prog != prog {
		t.Error("SSAAnalyzer.prog not set correctly")
	}

	if analyzer.sensitiveValues == nil {
		t.Error("SSAAnalyzer.sensitiveValues map not initialized")
	}

	if analyzer.sensitiveFields == nil {
		t.Error("SSAAnalyzer.sensitiveFields map not initialized")
	}

	if analyzer.sensitiveFuncs == nil {
		t.Error("SSAAnalyzer.sensitiveFuncs map not initialized")
	}
}

// TestMarkSensitive tests the sensitivity marking functionality.
func TestMarkSensitive(t *testing.T) {
	fset := token.NewFileSet()
	prog := ssa.NewProgram(fset, ssa.SanityCheckFunctions)
	_ = NewSSAAnalyzer(prog, fset)

	// TODO: This test needs actual SSA values for complete testing
	// Will implement after SSA construction is fully set up
	t.Skip("Need actual SSA values for complete test")
}

// TestGetTypeName tests type name extraction.
func TestGetTypeName(t *testing.T) {
	tests := []struct {
		name     string
		typ      types.Type
		expected string
	}{
		{
			name:     "named type",
			typ:      types.NewNamed(types.NewTypeName(0, nil, "User", nil), types.NewStruct(nil, nil), nil),
			expected: "User",
		},
		{
			name:     "pointer to named type",
			typ:      types.NewPointer(types.NewNamed(types.NewTypeName(0, nil, "User", nil), types.NewStruct(nil, nil), nil)),
			expected: "User",
		},
		{
			name:     "basic type",
			typ:      types.Typ[types.String],
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getTypeName(tt.typ)
			if got != tt.expected {
				t.Errorf("getTypeName() = %q, want %q", got, tt.expected)
			}
		})
	}
}
