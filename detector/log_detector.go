package detector

import (
	"go/ast"
	"go/types"

	"golang.org/x/tools/go/analysis"
)

// LogDetector detects logging function calls and identifies their arguments
type LogDetector struct {
	pass *analysis.Pass
}

// NewLogDetector creates a new LogDetector
func NewLogDetector(pass *analysis.Pass) *LogDetector {
	return &LogDetector{
		pass: pass,
	}
}

// IsLogCall checks if a call expression is a logging function call
// This consolidates checks for slog, log, and fmt packages
func (ld *LogDetector) IsLogCall(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}

	// Use type information to accurately verify the call
	obj := ld.pass.TypesInfo.Uses[sel.Sel]
	if obj == nil {
		return false
	}

	fn, ok := obj.(*types.Func)
	if !ok {
		return false
	}

	pkg := fn.Pkg()
	// Add nil check for package to handle build constraint issues
	if pkg == nil {
		return false
	}

	pkgPath := pkg.Path()
	funcName := sel.Sel.Name

	// Check for slog package calls
	if pkgPath == "log/slog" {
		return isSlogStyleMethod(funcName)
	}

	// Check for log package calls
	if pkgPath == "log" {
		return isLogStyleMethod(funcName)
	}

	// Check for fmt package calls
	if pkgPath == "fmt" {
		return isFmtStyleMethod(funcName)
	}

	// Check if this is a method on *slog.Logger type
	if sig, ok := fn.Type().(*types.Signature); ok {
		recv := sig.Recv()
		if recv != nil {
			if isSlogLoggerType(recv.Type()) && isSlogStyleMethod(funcName) {
				return true
			}
			if isLogLoggerType(recv.Type()) && isLogStyleMethod(funcName) {
				return true
			}
		}
	}

	return false
}

// Helper functions for method name checking

func isSlogStyleMethod(name string) bool {
	return name == "Info" || name == "Error" ||
		name == "Warn" || name == "Debug" ||
		name == "InfoContext" || name == "ErrorContext" ||
		name == "WarnContext" || name == "DebugContext" ||
		name == "Log" || name == "LogAttrs"
}

func isLogStyleMethod(name string) bool {
	return name == "Fatal" || name == "Fatalf" || name == "Fatalln" ||
		name == "Panic" || name == "Panicf" || name == "Panicln" ||
		name == "Print" || name == "Printf" || name == "Println" ||
		name == "Output"
}

func isFmtStyleMethod(name string) bool {
	return name == "Fprint" || name == "Fprintf" ||
		name == "Fprintln" || name == "Print" ||
		name == "Printf" || name == "Println"
}

func isSlogLoggerType(t types.Type) bool {
	// Handle pointer type
	ptr, ok := t.(*types.Pointer)
	if !ok {
		return false
	}

	// Get the underlying named type
	named, ok := ptr.Elem().(*types.Named)
	if !ok {
		return false
	}

	// Check if it's slog.Logger
	obj := named.Obj()
	if obj == nil || obj.Name() != "Logger" {
		return false
	}

	pkg := obj.Pkg()
	if pkg == nil {
		return false
	}

	return pkg.Path() == "log/slog"
}

func isLogLoggerType(t types.Type) bool {
	// Handle pointer type
	ptr, ok := t.(*types.Pointer)
	if !ok {
		return false
	}

	// Get the underlying named type
	named, ok := ptr.Elem().(*types.Named)
	if !ok {
		return false
	}

	// Check if it's log.Logger
	obj := named.Obj()
	if obj == nil || obj.Name() != "Logger" {
		return false
	}

	pkg := obj.Pkg()
	if pkg == nil {
		return false
	}

	return pkg.Path() == "log"
}
