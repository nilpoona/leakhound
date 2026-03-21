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
	// Use multiple passes to handle nested function calls
	maxPasses := 5 // Limit iterations to prevent infinite loops
	changed := true

	for pass := 0; pass < maxPasses && changed; pass++ {
		changed = false
		visitedFuncs := make(map[types.Object]bool) // Reset visited for each pass

		for funcObj, funcDecl := range da.funcDefs {
			beforeCount := len(da.sensitiveVars)
			da.analyzeFunctionCalls(funcObj, funcDecl, visitedFuncs)
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
		params := calledFuncDecl.Type.Params.List
		paramIdx := 0

		for _, arg := range call.Args {
			if paramIdx >= len(params) {
				break
			}

			param := params[paramIdx]

			// Check if this argument is sensitive
			if source := da.checker.checkSensitiveExpr(arg, da.sensitiveVars, da.sensitiveFuncs); source != nil {
				// Mark each parameter name as sensitive
				for _, paramName := range param.Names {
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

			// Move to next parameter
			if len(param.Names) > 0 {
				paramIdx++
			}
		}

		return true
	})
}
