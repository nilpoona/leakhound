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
	checker          *SensitivityChecker
	sensitiveVars    map[*types.Var]SensitiveSource
	sensitiveFuncs   map[types.Object]SensitiveSource
	sensitiveFuncPos map[sensitiveReturnKey]SensitiveSource // position-aware multi-return tracking
	sensitiveParams  map[*types.Var]SensitiveSource
	funcDefs         map[types.Object]*ast.FuncDecl
	currentFunc      types.Object // Traversal context: only used during collection
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
	// Multi-value function call: v, err := f()
	// AST: len(Rhs)==1 with a single CallExpr, len(Lhs)>1
	if len(assign.Rhs) == 1 && len(assign.Lhs) > 1 {
		if call, ok := assign.Rhs[0].(*ast.CallExpr); ok {
			fc.collectMultiValueAssignment(assign.Lhs, call)
			return
		}
	}

	// Single-value assignments: variable := expr
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

// collectMultiValueAssignment handles v, err := f() by mapping each LHS variable
// to the corresponding return position in sensitiveFuncPos.
func (fc *FactCollector) collectMultiValueAssignment(lhs []ast.Expr, call *ast.CallExpr) {
	funObj := fc.checker.getFunctionObject(call.Fun)
	if funObj == nil {
		return
	}
	for i, l := range lhs {
		ident, ok := l.(*ast.Ident)
		if !ok {
			continue
		}
		varObj, ok := fc.checker.pass.TypesInfo.Defs[ident].(*types.Var)
		if !ok || varObj == nil {
			continue
		}
		key := sensitiveReturnKey{funcObj: funObj, index: i}
		if source, found := fc.sensitiveFuncPos[key]; found {
			fc.sensitiveVars[varObj] = source
		}
	}
}

// CollectReturn analyzes a return statement for sensitive data
func (fc *FactCollector) CollectReturn(ret *ast.ReturnStmt) {
	if fc.currentFunc == nil {
		return
	}

	if len(ret.Results) == 1 {
		// Single return: mark the function itself as sensitive (existing behavior)
		if source := fc.checker.checkSensitiveExpr(ret.Results[0], fc.sensitiveVars, fc.sensitiveFuncs); source != nil {
			fc.sensitiveFuncs[fc.currentFunc] = *source
		}
		return
	}

	// Multi-value return: record sensitivity per position
	for i, result := range ret.Results {
		if source := fc.checker.checkSensitiveExpr(result, fc.sensitiveVars, fc.sensitiveFuncs); source != nil {
			key := sensitiveReturnKey{funcObj: fc.currentFunc, index: i}
			fc.sensitiveFuncPos[key] = *source
		}
	}
}

// CollectRangeStmt analyzes a range statement for sensitive data propagation
// If the ranged-over expression is sensitive, the range variables inherit sensitivity
func (fc *FactCollector) CollectRangeStmt(rangeStmt *ast.RangeStmt) {
	// Check if the ranged-over expression (X) is sensitive
	if rangeStmt.X == nil {
		return
	}

	source := fc.checker.checkSensitiveExpr(rangeStmt.X, fc.sensitiveVars, fc.sensitiveFuncs)
	if source == nil {
		return
	}

	// Mark the Value variable (element) as sensitive
	// For: for _, v := range vals { ... }
	//      Value is v, Key is _ (blank identifier)
	if rangeStmt.Value != nil {
		if ident, ok := rangeStmt.Value.(*ast.Ident); ok {
			if obj := fc.checker.pass.TypesInfo.Defs[ident]; obj != nil {
				if v, ok := obj.(*types.Var); ok {
					// Create new source with updated flow path
					newSource := SensitiveSource{
						FieldName: source.FieldName,
						Position:  rangeStmt.Value.Pos(),
						FlowPath:  append(append([]string{}, source.FlowPath...), "range variable '"+ident.Name+"'"),
					}
					fc.sensitiveVars[v] = newSource
				}
			}
		}
	}

	// Also mark the Key variable (index) as sensitive if present
	// This handles cases like: for i, v := range vals { ... }
	if rangeStmt.Key != nil {
		if ident, ok := rangeStmt.Key.(*ast.Ident); ok {
			if obj := fc.checker.pass.TypesInfo.Defs[ident]; obj != nil {
				if v, ok := obj.(*types.Var); ok {
					// For map ranges, the key might be sensitive
					// For slice/array ranges, the key is just an index (int), but we track it anyway for consistency
					newSource := SensitiveSource{
						FieldName: source.FieldName,
						Position:  rangeStmt.Key.Pos(),
						FlowPath:  append(append([]string{}, source.FlowPath...), "range key '"+ident.Name+"'"),
					}
					fc.sensitiveVars[v] = newSource
				}
			}
		}
	}
}
