package detector

import (
	"go/ast"
	"go/types"
)

// FactCollector collects facts from a single AST traversal.
// It records variable assignments, return statements, and function definitions.
// Sensitivity checks are delegated to SensitivityChecker.
// The currentFunc field is owned by this type and used only during collection phase.
type FactCollector struct {
	checker         *SensitivityChecker
	sensitiveVars   map[*types.Var]SensitiveSource
	sensitiveFuncs  map[types.Object]SensitiveSource
	sensitiveParams map[*types.Var]SensitiveSource
	funcDefs        map[types.Object]*ast.FuncDecl
	currentFunc     types.Object // Traversal context: only used during collection
}

// CollectFunctionDef registers a function definition for later analysis
func (fc *FactCollector) CollectFunctionDef(funcDecl *ast.FuncDecl) {
	if funcDecl.Name == nil {
		return
	}

	obj := fc.checker.pass.TypesInfo.Defs[funcDecl.Name]
	if obj == nil {
		return
	}

	fc.funcDefs[obj] = funcDecl
}

// SetCurrentFunction sets the current function context
func (fc *FactCollector) SetCurrentFunction(funcObj types.Object) {
	fc.currentFunc = funcObj
}

// CollectAssignment analyzes an assignment statement for sensitive data
func (fc *FactCollector) CollectAssignment(assign *ast.AssignStmt) {
	// Handle assignments: variable := expr
	for i, lhs := range assign.Lhs {
		if i >= len(assign.Rhs) {
			continue
		}
		rhs := assign.Rhs[i]

		// Get the variable being assigned to
		var varObj *types.Var
		switch l := lhs.(type) {
		case *ast.Ident:
			if obj := fc.checker.pass.TypesInfo.Defs[l]; obj != nil {
				if v, ok := obj.(*types.Var); ok {
					varObj = v
				}
			}
		}

		if varObj == nil {
			continue
		}

		// Check if RHS is a sensitive field access
		if source := fc.checker.checkSensitiveExpr(rhs, fc.sensitiveVars, fc.sensitiveFuncs); source != nil {
			fc.sensitiveVars[varObj] = *source
		}
	}
}

// CollectReturn analyzes a return statement for sensitive data
func (fc *FactCollector) CollectReturn(ret *ast.ReturnStmt) {
	// Only handle single return values for now (per spec)
	if len(ret.Results) != 1 {
		return
	}

	// Check if the returned expression is sensitive
	if source := fc.checker.checkSensitiveExpr(ret.Results[0], fc.sensitiveVars, fc.sensitiveFuncs); source != nil {
		// Mark the current function as returning sensitive data
		if fc.currentFunc != nil {
			fc.sensitiveFuncs[fc.currentFunc] = *source
		}
	}
}
