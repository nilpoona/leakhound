package detector

import (
	"go/ast"
	"go/token"
	"go/types"

	"golang.org/x/tools/go/packages"
)

// WorldView holds aggregated cross-package state for whole-program analysis.
//
// It is the central data structure for How E (whole-program AST) analysis, per
// docs/design/cross-package-tracking.md. Aggregating state across packages lets
// data flow propagate beyond package boundaries: when package B calls
// pkgA.Func(secret), the sensitivity of pkgA.Func's parameter and return value
// are visible to package B during detection.
//
// Per design doc §7(c), the WorldView is the abstraction layer that future
// SSA-based engines can replace without touching collectors or reporters.
type WorldView struct {
	Fset     *token.FileSet
	Packages []*packages.Package

	// Aggregated facts, populated by WholeProgramCollector.
	// types.Object identity is globally unique across packages, so a single
	// map per kind is sufficient.
	sensitiveFields  map[sensitiveField]bool
	sensitiveVars    map[*types.Var]SensitiveSource
	sensitiveFuncs   map[types.Object]SensitiveSource
	sensitiveFuncPos map[sensitiveReturnKey]SensitiveSource
	sensitiveParams  map[*types.Var]SensitiveSource

	// sinkParams marks function parameters that are forwarded (directly or
	// transitively) to a logging call inside their owning function. These
	// drive LH0006 (cross-package sensitive sink) detection.
	sinkParams map[*types.Var]bool

	// funcDefs maps function objects (including methods) to their AST decls.
	funcDefs map[types.Object]*ast.FuncDecl

	// funcPkg routes a function object to the package that owns its body,
	// used to resolve cross-package position information and call sites.
	funcPkg map[types.Object]*packages.Package

	// pkgByPath indexes loaded packages by import path for quick lookup.
	pkgByPath map[string]*packages.Package
}

// NewWorldView creates an empty world view to be populated by
// WholeProgramCollector.
func NewWorldView(fset *token.FileSet, pkgs []*packages.Package) *WorldView {
	w := &WorldView{
		Fset:             fset,
		Packages:         pkgs,
		sensitiveFields:  make(map[sensitiveField]bool),
		sensitiveVars:    make(map[*types.Var]SensitiveSource),
		sensitiveFuncs:   make(map[types.Object]SensitiveSource),
		sensitiveFuncPos: make(map[sensitiveReturnKey]SensitiveSource),
		sensitiveParams:  make(map[*types.Var]SensitiveSource),
		sinkParams:       make(map[*types.Var]bool),
		funcDefs:         make(map[types.Object]*ast.FuncDecl),
		funcPkg:          make(map[types.Object]*packages.Package),
		pkgByPath:        make(map[string]*packages.Package),
	}
	for _, p := range pkgs {
		if p == nil {
			continue
		}
		w.pkgByPath[p.PkgPath] = p
	}
	return w
}

// SensitiveFields returns the shared sensitive-field map.
func (w *WorldView) SensitiveFields() map[sensitiveField]bool { return w.sensitiveFields }

// SensitiveVars returns the shared sensitive-variable map.
func (w *WorldView) SensitiveVars() map[*types.Var]SensitiveSource { return w.sensitiveVars }

// SensitiveFuncs returns the shared sensitive-function map (single return).
func (w *WorldView) SensitiveFuncs() map[types.Object]SensitiveSource { return w.sensitiveFuncs }

// SensitiveFuncPos returns the shared multi-return-position map.
func (w *WorldView) SensitiveFuncPos() map[sensitiveReturnKey]SensitiveSource {
	return w.sensitiveFuncPos
}

// SensitiveParams returns the shared sensitive-parameter map.
func (w *WorldView) SensitiveParams() map[*types.Var]SensitiveSource { return w.sensitiveParams }

// SinkParams returns the shared sink-parameter set (for LH0006 detection).
func (w *WorldView) SinkParams() map[*types.Var]bool { return w.sinkParams }

// FuncDefs returns the shared function-definition map.
func (w *WorldView) FuncDefs() map[types.Object]*ast.FuncDecl { return w.funcDefs }

// PackageOf returns the package that owns the body of the given function
// object. Returns nil for cross-package callees whose definition wasn't loaded
// (e.g. when running without NeedDeps).
func (w *WorldView) PackageOf(obj types.Object) *packages.Package {
	return w.funcPkg[obj]
}

// RegisterFunc associates a function object with its owning package and
// declaration. Called once per loaded function definition.
func (w *WorldView) RegisterFunc(obj types.Object, decl *ast.FuncDecl, pkg *packages.Package) {
	if obj == nil {
		return
	}
	w.funcDefs[obj] = decl
	w.funcPkg[obj] = pkg
}
