package detector

import (
	"fmt"
	"go/ast"
	"go/types"

	"golang.org/x/tools/go/analysis"
)

// DataFlowAnalyzer performs data flow analysis to propagate sensitivity through
// function calls. It takes facts collected by FactCollector and analyzes how
// sensitive data flows through function parameters and return values.
type DataFlowAnalyzer struct {
	pass            *analysis.Pass
	checker         *SensitivityChecker
	sensitiveVars   map[*types.Var]SensitiveSource
	sensitiveFuncs  map[types.Object]SensitiveSource
	sensitiveParams map[*types.Var]SensitiveSource
	funcDefs        map[types.Object]*ast.FuncDecl
}

// Analyze performs iterative data flow analysis.
// visitedFuncs is created and managed locally for each analysis pass.
func (da *DataFlowAnalyzer) Analyze() {
	// Track function calls to propagate sensitive parameters
	// Use multiple passes to handle nested function calls and range variables
	maxPasses := 5 // Limit iterations to prevent infinite loops
	changed := true

	for pass := 0; pass < maxPasses && changed; pass++ {
		changed = false
		visitedFuncs := make(map[types.Object]bool) // Reset visited for each pass

		for funcObj, funcDecl := range da.funcDefs {
			beforeCount := len(da.sensitiveVars)
			da.analyzeFunctionCalls(funcObj, funcDecl, visitedFuncs)
			// Also propagate sensitivity through range statements
			da.analyzeRangeStatements(funcDecl)
			if len(da.sensitiveVars) > beforeCount {
				changed = true
			}
		}
	}
}

// analyzeFunctionCalls tracks sensitive variables passed as function parameters
func (da *DataFlowAnalyzer) analyzeFunctionCalls(funcObj types.Object, funcDecl *ast.FuncDecl, visitedFuncs map[types.Object]bool) {
	// Check if already visited to prevent infinite recursion
	if visitedFuncs[funcObj] {
		return
	}
	visitedFuncs[funcObj] = true

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
		calledFunc := da.checker.getFunctionObject(call.Fun)
		if calledFunc == nil {
			return true
		}

		// Only track same-package functions
		if calledFunc.Pkg() == nil || calledFunc.Pkg() != da.pass.Pkg {
			return true
		}

		// Get the function definition
		calledFuncDecl, found := da.funcDefs[calledFunc]
		if !found || calledFuncDecl.Type == nil || calledFuncDecl.Type.Params == nil {
			return true
		}

		// Map arguments to parameters
		// Build a flat list of parameter names and check for variadic
		var paramNames []*ast.Ident
		var isVariadic bool
		for i, field := range calledFuncDecl.Type.Params.List {
			paramNames = append(paramNames, field.Names...)
			// Check if this is the last parameter and is variadic
			if i == len(calledFuncDecl.Type.Params.List)-1 {
				if _, ok := field.Type.(*ast.Ellipsis); ok {
					isVariadic = true
				}
			}
		}

		// Map each argument to its corresponding parameter
		for argIdx, arg := range call.Args {
			var paramName *ast.Ident

			// Regular parameter mapping
			if argIdx < len(paramNames) {
				paramName = paramNames[argIdx]
			} else if isVariadic && len(paramNames) > 0 {
				// Variadic parameter: all excess arguments map to the last parameter
				paramName = paramNames[len(paramNames)-1]
			} else {
				// No more parameters to map
				break
			}

			// Check if this argument is sensitive
			if source := da.checker.checkSensitiveExpr(arg, da.sensitiveVars, da.sensitiveFuncs); source != nil {
				// Mark the corresponding parameter as sensitive
				if paramObj := da.checker.pass.TypesInfo.Defs[paramName]; paramObj != nil {
					if v, ok := paramObj.(*types.Var); ok {
						// Create new source with updated flow path
						newSource := SensitiveSource{
							FieldName: source.FieldName,
							Position:  arg.Pos(),
							FlowPath:  append(append([]string{}, source.FlowPath...), fmt.Sprintf("parameter '%s'", paramName.Name)),
						}
						da.sensitiveParams[v] = newSource
						da.sensitiveVars[v] = newSource
					}
				}
			}
		}

		return true
	})
}

// analyzeRangeStatements propagates sensitivity through range statements
// This handles cases where a sensitive slice/array/map is ranged over
func (da *DataFlowAnalyzer) analyzeRangeStatements(funcDecl *ast.FuncDecl) {
	if funcDecl.Body == nil {
		return
	}

	ast.Inspect(funcDecl.Body, func(n ast.Node) bool {
		rangeStmt, ok := n.(*ast.RangeStmt)
		if !ok {
			return true
		}

		// Check if the ranged-over expression is sensitive
		if rangeStmt.X == nil {
			return true
		}

		// Use a temporary SensitivityChecker to evaluate the expression
		checker := &SensitivityChecker{
			pass:            da.pass,
			sensitiveFields: make(map[sensitiveField]bool), // Not needed for var checking
		}

		source := checker.checkSensitiveExpr(rangeStmt.X, da.sensitiveVars, nil)
		if source == nil {
			return true
		}

		// Mark the Value variable (element) as sensitive
		if rangeStmt.Value != nil {
			if ident, ok := rangeStmt.Value.(*ast.Ident); ok {
				if obj := da.pass.TypesInfo.Defs[ident]; obj != nil {
					if v, ok := obj.(*types.Var); ok {
						// Only add if not already tracked (avoid overwriting)
						if _, exists := da.sensitiveVars[v]; !exists {
							newSource := SensitiveSource{
								FieldName: source.FieldName,
								Position:  rangeStmt.Value.Pos(),
								FlowPath:  append(append([]string{}, source.FlowPath...), "range variable '"+ident.Name+"'"),
							}
							da.sensitiveVars[v] = newSource
						}
					}
				}
			}
		}

		// Mark the Key variable as sensitive if present
		if rangeStmt.Key != nil {
			if ident, ok := rangeStmt.Key.(*ast.Ident); ok {
				if obj := da.pass.TypesInfo.Defs[ident]; obj != nil {
					if v, ok := obj.(*types.Var); ok {
						if _, exists := da.sensitiveVars[v]; !exists {
							newSource := SensitiveSource{
								FieldName: source.FieldName,
								Position:  rangeStmt.Key.Pos(),
								FlowPath:  append(append([]string{}, source.FlowPath...), "range key '"+ident.Name+"'"),
							}
							da.sensitiveVars[v] = newSource
						}
					}
				}
			}
		}

		return true
	})
}
