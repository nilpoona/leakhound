package slogchecker

import (
	"go/ast"
	"go/types"

	"golang.org/x/tools/go/analysis"
)

// IsSlogCall checks if this is a log function call from the slog package or a custom logger
// It detects:
// 1. Standard slog package calls (e.g., slog.Info, slog.Error)
// 2. Custom logger method calls (e.g., logger.Info, logger.Error)
func IsSlogCall(call *ast.CallExpr, pass *analysis.Pass) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}

	// Check if the method name matches slog-style logging methods
	funcName := sel.Sel.Name
	if !isSlogStyleMethod(funcName) {
		return false
	}

	// Use type information to accurately verify the call
	obj := pass.TypesInfo.Uses[sel.Sel]
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

	// Accept both standard slog package and custom logger types
	// Standard slog: pkg.Path() == "log/slog"
	// Custom logger: any package with matching method names
	return pkg.Path() == "log/slog" || isSlogStyleMethod(funcName)
}

// isSlogStyleMethod checks if the method name matches slog-style logging methods
func isSlogStyleMethod(name string) bool {
	return name == "Info" || name == "Error" ||
		name == "Warn" || name == "Debug" ||
		name == "InfoContext" || name == "ErrorContext" ||
		name == "WarnContext" || name == "DebugContext" ||
		name == "Log" || name == "LogAttrs"
}
