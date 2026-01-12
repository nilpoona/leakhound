package detector

import (
	"go/ast"
	"go/types"
	"slices"

	"github.com/nilpoona/leakhound/config"
	"golang.org/x/tools/go/analysis"
)

// LogDetector detects logging function calls and identifies their arguments
type LogDetector struct {
	pass   *analysis.Pass
	config *config.Config
}

// NewLogDetector creates a new LogDetector
func NewLogDetector(pass *analysis.Pass) *LogDetector {
	return &LogDetector{
		pass:   pass,
		config: nil,
	}
}

// NewLogDetectorWithConfig creates a new LogDetector with custom configuration
func NewLogDetectorWithConfig(pass *analysis.Pass, cfg *config.Config) *LogDetector {
	return &LogDetector{
		pass:   pass,
		config: cfg,
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

	// Check custom targets from configuration
	if ld.config != nil {
		return ld.isCustomLogCall(pkgPath, funcName, fn)
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

// isCustomLogCall checks if the call matches any custom target configuration
func (ld *LogDetector) isCustomLogCall(pkgPath, funcName string, fn *types.Func) bool {
	for _, target := range ld.config.Targets {
		if target.Package != pkgPath {
			continue
		}

		// Check if it's a package-level function
		if slices.Contains(target.Functions, funcName) {
			return true
		}

		// Check if it's a method on a configured receiver type
		sig, ok := fn.Type().(*types.Signature)
		if !ok {
			continue
		}

		recv := sig.Recv()
		if recv == nil {
			continue
		}

		for _, method := range target.Methods {
			if ld.isMatchingReceiverType(recv.Type(), pkgPath, method.Receiver) {
				if slices.Contains(method.Names, funcName) {
					return true
				}
			}
		}
	}

	return false
}

// isMatchingReceiverType checks if the receiver type matches the configured receiver
func (ld *LogDetector) isMatchingReceiverType(t types.Type, pkgPath, configReceiver string) bool {
	// configReceiver can be "*Logger" or "Logger"
	isPointer := false
	typeName := configReceiver
	if len(configReceiver) > 0 && configReceiver[0] == '*' {
		isPointer = true
		typeName = configReceiver[1:]
	}

	// Check pointer type
	if isPointer {
		ptr, ok := t.(*types.Pointer)
		if !ok {
			return false
		}
		t = ptr.Elem()
	}

	// Get the named type
	named, ok := t.(*types.Named)
	if !ok {
		return false
	}

	// Check if the type name matches
	obj := named.Obj()
	if obj == nil || obj.Name() != typeName {
		return false
	}

	// Check if the package matches
	pkg := obj.Pkg()
	if pkg == nil {
		return false
	}

	return pkg.Path() == pkgPath
}
