package logchecker

import (
	"go/ast"
	"go/types"

	"golang.org/x/tools/go/analysis"
)

// IsLogCall checks if this is a log function call from the log package or a *log.Logger method
// It detects:
// 1. Standard log package calls (e.g., log.Print, log.Fatal)
// 2. *log.Logger type method calls (e.g., logger.Print, logger.Fatal where logger is *log.Logger)
func IsLogCall(call *ast.CallExpr, pass *analysis.Pass) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}

	// Check if the method name matches log-style logging methods
	funcName := sel.Sel.Name
	if !isLogStyleMethod(funcName) {
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

	// Standard log package call (e.g., log.Print)
	if pkg.Path() == "log" {
		return true
	}

	// Check if this is a method on *log.Logger type
	sig, ok := fn.Type().(*types.Signature)
	if !ok {
		return false
	}

	recv := sig.Recv()
	if recv == nil {
		return false
	}

	// Check if the receiver is *log.Logger
	return isLogLoggerType(recv.Type())
}

// isLogLoggerType checks if the given type is *log.Logger
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

// isLogStyleMethod checks if the method name matches log-style logging methods
func isLogStyleMethod(name string) bool {
	return name == "Fatal" || name == "Fatalf" || name == "Fatalln" ||
		name == "Panic" || name == "Panicf" || name == "Panicln" ||
		name == "Print" || name == "Printf" || name == "Println" ||
		name == "Output"
}
