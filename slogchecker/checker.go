package slogchecker

import (
	"go/ast"
	"go/types"

	"golang.org/x/tools/go/analysis"
)

// IsSlogCall checks if this is a log function call from the slog package
func IsSlogCall(call *ast.CallExpr, pass *analysis.Pass) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}

	// Use type information to accurately verify if it's the slog package
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

	// Safely get package path
	if pkg.Path() != "log/slog" {
		return false
	}

	// Check log function name
	funcName := sel.Sel.Name
	return funcName == "Info" || funcName == "Error" ||
		funcName == "Warn" || funcName == "Debug" ||
		funcName == "InfoContext" || funcName == "ErrorContext" ||
		funcName == "WarnContext" || funcName == "DebugContext" ||
		funcName == "Log" || funcName == "LogAttrs"
}
