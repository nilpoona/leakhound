package detector

import (
	"fmt"
	"go/ast"
	"go/types"

	"golang.org/x/tools/go/analysis"
)

// SensitivityChecker checks if expressions are sensitive based on field tags.
// This type is stateless regarding data flow - it only queries type information
// and a pre-built sensitiveFields map. It does not update any tracking maps.
type SensitivityChecker struct {
	pass            *analysis.Pass
	sensitiveFields map[sensitiveField]bool
}

// checkSensitiveExpr checks if an expression is sensitive.
// It takes sensitiveVars and sensitiveFuncs as parameters to avoid dependency
// on VarTracker's internal state. This enables testing the checker independently.
func (sc *SensitivityChecker) checkSensitiveExpr(
	expr ast.Expr,
	vars map[*types.Var]SensitiveSource,
	funcs map[types.Object]SensitiveSource,
) *SensitiveSource {
	switch e := expr.(type) {
	case *ast.SelectorExpr:
		// Direct field access: user.Password
		return sc.checkSensitiveFieldAccess(e)

	case *ast.Ident:
		// Variable reference: password
		if obj := sc.pass.TypesInfo.Uses[e]; obj != nil {
			if v, ok := obj.(*types.Var); ok {
				if source, found := vars[v]; found {
					return &source
				}
			}
		}

	case *ast.CallExpr:
		// Function call: getPassword(user)
		if funObj := sc.getFunctionObject(e.Fun); funObj != nil {
			if source, found := funcs[funObj]; found {
				return &source
			}
		}
	}

	return nil
}

// checkSensitiveFieldAccess checks if a selector expression is a sensitive field access
func (sc *SensitivityChecker) checkSensitiveFieldAccess(sel *ast.SelectorExpr) *SensitiveSource {
	// Get the type of the base expression
	tv, ok := sc.pass.TypesInfo.Types[sel.X]
	if !ok {
		return nil
	}

	typ := tv.Type
	if ptr, ok := typ.(*types.Pointer); ok {
		typ = ptr.Elem()
	}

	named, ok := typ.(*types.Named)
	if !ok {
		return nil
	}

	obj := named.Obj()
	if obj == nil {
		return nil
	}

	typeName := obj.Name()
	fieldName := sel.Sel.Name

	// Check if this field is sensitive
	sf := sensitiveField{
		typeName:  typeName,
		fieldName: fieldName,
	}

	if sc.sensitiveFields[sf] {
		return &SensitiveSource{
			FieldName: fmt.Sprintf("%s.%s", typeName, fieldName),
			Position:  sel.Pos(),
			FlowPath:  []string{fmt.Sprintf("%s.%s", typeName, fieldName)},
		}
	}

	return nil
}

// getFunctionObject gets the function object from a call expression
func (sc *SensitivityChecker) getFunctionObject(fun ast.Expr) types.Object {
	switch f := fun.(type) {
	case *ast.Ident:
		if obj := sc.pass.TypesInfo.Uses[f]; obj != nil {
			return obj
		}
	case *ast.SelectorExpr:
		if obj := sc.pass.TypesInfo.Uses[f.Sel]; obj != nil {
			return obj
		}
	}
	return nil
}
