package detector

import (
	"go/ast"
	"go/types"

	"golang.org/x/tools/go/analysis"
)

// VarTracker tracks sensitive data flow through variables and function parameters
type VarTracker struct {
	checker  *SensitivityChecker
	facts    *FactCollector
	analyzer *DataFlowAnalyzer

	// Tracking maps (shared with FactCollector and DataFlowAnalyzer)
	sensitiveVars  map[*types.Var]SensitiveSource
	sensitiveFuncs map[types.Object]SensitiveSource
}

// NewVarTracker creates a new VarTracker
func NewVarTracker(pass *analysis.Pass, sensitiveFields map[sensitiveField]bool) *VarTracker {
	// Create shared maps
	sensitiveVars := make(map[*types.Var]SensitiveSource)
	sensitiveFuncs := make(map[types.Object]SensitiveSource)
	sensitiveParams := make(map[*types.Var]SensitiveSource)
	funcDefs := make(map[types.Object]*ast.FuncDecl)

	checker := &SensitivityChecker{
		pass:            pass,
		sensitiveFields: sensitiveFields,
	}

	facts := &FactCollector{
		checker:         checker,
		sensitiveVars:   sensitiveVars,
		sensitiveFuncs:  sensitiveFuncs,
		sensitiveParams: sensitiveParams,
		funcDefs:        funcDefs,
	}

	analyzer := &DataFlowAnalyzer{
		pass:            pass,
		checker:         checker,
		sensitiveVars:   sensitiveVars,
		sensitiveFuncs:  sensitiveFuncs,
		sensitiveParams: sensitiveParams,
		funcDefs:        funcDefs,
	}

	return &VarTracker{
		checker:        checker,
		facts:          facts,
		analyzer:       analyzer,
		sensitiveVars:  sensitiveVars,
		sensitiveFuncs: sensitiveFuncs,
	}
}

// CollectFunctionDef delegates to FactCollector
func (vt *VarTracker) CollectFunctionDef(funcDecl *ast.FuncDecl) {
	vt.facts.CollectFunctionDef(funcDecl)
}

// SetCurrentFunction delegates to FactCollector
func (vt *VarTracker) SetCurrentFunction(funcObj types.Object) {
	vt.facts.SetCurrentFunction(funcObj)
}

// CollectAssignment delegates to FactCollector
func (vt *VarTracker) CollectAssignment(assign *ast.AssignStmt) {
	vt.facts.CollectAssignment(assign)
}

// CollectReturn delegates to FactCollector
func (vt *VarTracker) CollectReturn(ret *ast.ReturnStmt) {
	vt.facts.CollectReturn(ret)
}

// AnalyzeDataFlow delegates to DataFlowAnalyzer
func (vt *VarTracker) AnalyzeDataFlow() {
	vt.analyzer.Analyze()
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
	funObj := vt.checker.getFunctionObject(call.Fun)
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
