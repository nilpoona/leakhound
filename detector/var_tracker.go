package detector

import (
	"fmt"
	"go/ast"
	"go/types"

	"golang.org/x/tools/go/analysis"
)

// VarTracker tracks sensitive data flow through variables and function parameters
type VarTracker struct {
	pass *analysis.Pass

	// Tracking maps
	sensitiveFields map[sensitiveField]bool
	sensitiveVars   map[*types.Var]SensitiveSource   // Variables assigned from sensitive fields
	sensitiveFuncs  map[types.Object]SensitiveSource // Functions that return sensitive values
	sensitiveParams map[*types.Var]SensitiveSource   // Function parameters that receive sensitive values

	// Function definitions for parameter tracking
	funcDefs map[types.Object]*ast.FuncDecl

	// Current context during traversal
	currentFunc types.Object

	// Visited tracking to prevent infinite recursion
	visitedFuncs map[types.Object]bool
}

// NewVarTracker creates a new VarTracker
func NewVarTracker(pass *analysis.Pass, sensitiveFields map[sensitiveField]bool) *VarTracker {
	return &VarTracker{
		pass:            pass,
		sensitiveFields: sensitiveFields,
		sensitiveVars:   make(map[*types.Var]SensitiveSource),
		sensitiveFuncs:  make(map[types.Object]SensitiveSource),
		sensitiveParams: make(map[*types.Var]SensitiveSource),
		funcDefs:        make(map[types.Object]*ast.FuncDecl),
		visitedFuncs:    make(map[types.Object]bool),
	}
}

// CollectFunctionDef registers a function definition for later analysis
func (vt *VarTracker) CollectFunctionDef(funcDecl *ast.FuncDecl) {
	if funcDecl.Name == nil {
		return
	}

	obj := vt.pass.TypesInfo.Defs[funcDecl.Name]
	if obj == nil {
		return
	}

	vt.funcDefs[obj] = funcDecl
}

// SetCurrentFunction sets the current function context
func (vt *VarTracker) SetCurrentFunction(funcObj types.Object) {
	vt.currentFunc = funcObj
}

// CollectAssignment analyzes an assignment statement for sensitive data
func (vt *VarTracker) CollectAssignment(assign *ast.AssignStmt) {
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
			if obj := vt.pass.TypesInfo.Defs[l]; obj != nil {
				if v, ok := obj.(*types.Var); ok {
					varObj = v
				}
			}
		}

		if varObj == nil {
			continue
		}

		// Check if RHS is a sensitive field access
		if source := vt.checkSensitiveExpr(rhs); source != nil {
			vt.sensitiveVars[varObj] = *source
		}
	}
}

// CollectReturn analyzes a return statement for sensitive data
func (vt *VarTracker) CollectReturn(ret *ast.ReturnStmt) {
	// Only handle single return values for now (per spec)
	if len(ret.Results) != 1 {
		return
	}

	// Check if the returned expression is sensitive
	if source := vt.checkSensitiveExpr(ret.Results[0]); source != nil {
		// Mark the current function as returning sensitive data
		if vt.currentFunc != nil {
			vt.sensitiveFuncs[vt.currentFunc] = *source
		}
	}
}

// checkSensitiveExpr checks if an expression is sensitive
func (vt *VarTracker) checkSensitiveExpr(expr ast.Expr) *SensitiveSource {
	switch e := expr.(type) {
	case *ast.SelectorExpr:
		// Direct field access: user.Password
		return vt.checkSensitiveFieldAccess(e)

	case *ast.Ident:
		// Variable reference: password
		if obj := vt.pass.TypesInfo.Uses[e]; obj != nil {
			if v, ok := obj.(*types.Var); ok {
				if source, found := vt.sensitiveVars[v]; found {
					return &source
				}
			}
		}

	case *ast.CallExpr:
		// Function call: getPassword(user)
		if funObj := vt.getFunctionObject(e.Fun); funObj != nil {
			if source, found := vt.sensitiveFuncs[funObj]; found {
				return &source
			}
		}
	}

	return nil
}

// checkSensitiveFieldAccess checks if a selector expression is a sensitive field access
func (vt *VarTracker) checkSensitiveFieldAccess(sel *ast.SelectorExpr) *SensitiveSource {
	// Get the type of the base expression
	tv, ok := vt.pass.TypesInfo.Types[sel.X]
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

	if vt.sensitiveFields[sf] {
		return &SensitiveSource{
			FieldName: fmt.Sprintf("%s.%s", typeName, fieldName),
			Position:  sel.Pos(),
			FlowPath:  []string{fmt.Sprintf("%s.%s", typeName, fieldName)},
		}
	}

	return nil
}

// getFunctionObject gets the function object from a call expression
func (vt *VarTracker) getFunctionObject(fun ast.Expr) types.Object {
	switch f := fun.(type) {
	case *ast.Ident:
		if obj := vt.pass.TypesInfo.Uses[f]; obj != nil {
			return obj
		}
	case *ast.SelectorExpr:
		if obj := vt.pass.TypesInfo.Uses[f.Sel]; obj != nil {
			return obj
		}
	}
	return nil
}

// AnalyzeDataFlow performs iterative data flow analysis
func (vt *VarTracker) AnalyzeDataFlow() {
	// Track function calls to propagate sensitive parameters
	// Use multiple passes to handle nested function calls
	maxPasses := 5 // Limit iterations to prevent infinite loops
	changed := true

	for pass := 0; pass < maxPasses && changed; pass++ {
		changed = false
		vt.visitedFuncs = make(map[types.Object]bool) // Reset visited for each pass

		for funcObj, funcDecl := range vt.funcDefs {
			beforeCount := len(vt.sensitiveVars)
			vt.analyzeFunctionCalls(funcObj, funcDecl)
			if len(vt.sensitiveVars) > beforeCount {
				changed = true
			}
		}
	}
}

// analyzeFunctionCalls tracks sensitive variables passed as function parameters
func (vt *VarTracker) analyzeFunctionCalls(funcObj types.Object, funcDecl *ast.FuncDecl) {
	// Update current function context
	oldFunc := vt.currentFunc
	vt.currentFunc = funcObj
	defer func() { vt.currentFunc = oldFunc }()

	// Check if already visited to prevent infinite recursion
	if vt.visitedFuncs[funcObj] {
		return
	}
	vt.visitedFuncs[funcObj] = true

	// Traverse function body to find calls
	if funcDecl.Body == nil {
		return
	}

	ast.Inspect(funcDecl.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		// Get the called function
		calledFunc := vt.getFunctionObject(call.Fun)
		if calledFunc == nil {
			return true
		}

		// Only track same-package functions
		if calledFunc.Pkg() == nil || calledFunc.Pkg() != vt.pass.Pkg {
			return true
		}

		// Get the function definition
		calledFuncDecl, found := vt.funcDefs[calledFunc]
		if !found || calledFuncDecl.Type == nil || calledFuncDecl.Type.Params == nil {
			return true
		}

		// Map arguments to parameters
		params := calledFuncDecl.Type.Params.List
		paramIdx := 0

		for _, arg := range call.Args {
			if paramIdx >= len(params) {
				break
			}

			param := params[paramIdx]

			// Check if this argument is sensitive
			if source := vt.checkSensitiveExpr(arg); source != nil {
				// Mark each parameter name as sensitive
				for _, paramName := range param.Names {
					if paramObj := vt.pass.TypesInfo.Defs[paramName]; paramObj != nil {
						if v, ok := paramObj.(*types.Var); ok {
							// Create new source with updated flow path
							newSource := SensitiveSource{
								FieldName: source.FieldName,
								Position:  arg.Pos(),
								FlowPath:  append(append([]string{}, source.FlowPath...), fmt.Sprintf("parameter '%s'", paramName.Name)),
							}
							vt.sensitiveParams[v] = newSource
							vt.sensitiveVars[v] = newSource
						}
					}
				}
			}

			// Move to next parameter
			if len(param.Names) > 0 {
				paramIdx++
			}
		}

		return true
	})
}

// IsSensitiveVar checks if a variable is sensitive
func (vt *VarTracker) IsSensitiveVar(obj types.Object) (SensitiveSource, bool) {
	if v, ok := obj.(*types.Var); ok {
		source, found := vt.sensitiveVars[v]
		return source, found
	}
	return SensitiveSource{}, false
}

// IsSensitiveCall checks if a function call returns sensitive data
func (vt *VarTracker) IsSensitiveCall(call *ast.CallExpr) (SensitiveSource, bool) {
	funObj := vt.getFunctionObject(call.Fun)
	if funObj == nil {
		return SensitiveSource{}, false
	}

	source, found := vt.sensitiveFuncs[funObj]
	return source, found
}

// GetSensitiveVars returns all tracked sensitive variables
func (vt *VarTracker) GetSensitiveVars() map[*types.Var]SensitiveSource {
	return vt.sensitiveVars
}
