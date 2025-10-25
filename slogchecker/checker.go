package slogchecker

import (
	"go/ast"
	"go/types"

	"golang.org/x/tools/go/analysis"
)

// IsSlogCall checks if this is a log function call from the slog package or a *slog.Logger method
// It detects:
// 1. Standard slog package calls (e.g., slog.Info, slog.Error)
// 2. *slog.Logger type method calls (e.g., logger.Info, logger.Error where logger is *slog.Logger)
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

	// Standard slog package call (e.g., slog.Info)
	if pkg.Path() == "log/slog" {
		return true
	}

	// Check if this is a method on *slog.Logger type
	sig, ok := fn.Type().(*types.Signature)
	if !ok {
		return false
	}

	recv := sig.Recv()
	if recv == nil {
		return false
	}

	// Check if the receiver is *slog.Logger
	return isSlogLoggerType(recv.Type())
}

// isSlogLoggerType checks if the given type is *slog.Logger
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

// isSlogStyleMethod checks if the method name matches slog-style logging methods
func isSlogStyleMethod(name string) bool {
	return name == "Info" || name == "Error" ||
		name == "Warn" || name == "Debug" ||
		name == "InfoContext" || name == "ErrorContext" ||
		name == "WarnContext" || name == "DebugContext" ||
		name == "Log" || name == "LogAttrs"
}
