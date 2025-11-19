package detector

import (
	"go/ast"
	"go/types"

	"golang.org/x/tools/go/analysis"
)

// DataFlowCollector orchestrates data flow information collection in a single AST pass
// This implements the Two-Phase Analysis Pattern:
// - Phase 1: Collection (single AST pass)
// - Phase 2: Analysis (processes collected data)
type DataFlowCollector struct {
	pass *analysis.Pass

	// Component delegates
	fieldCollector *FieldCollector
	varTracker     *VarTracker
	logDetector    *LogDetector
	detector       *Detector

	// Log calls collected during traversal (for single-pass optimization)
	logCalls []*ast.CallExpr
}

// NewDataFlowCollector creates a new collector with all components initialized
func NewDataFlowCollector(pass *analysis.Pass) *DataFlowCollector {
	fieldCollector := NewFieldCollector(pass)
	varTracker := NewVarTracker(pass, fieldCollector.GetSensitiveFields())
	logDetector := NewLogDetector(pass)
	detector := NewDetector(pass, fieldCollector.GetSensitiveFields(), varTracker)

	return &DataFlowCollector{
		pass:           pass,
		fieldCollector: fieldCollector,
		varTracker:     varTracker,
		logDetector:    logDetector,
		detector:       detector,
		logCalls:       make([]*ast.CallExpr, 0),
	}
}

// Collect performs single-pass AST traversal to collect all information
// This implements Phase 1 of the Two-Phase Analysis Pattern
func (c *DataFlowCollector) Collect() {
	// Phase 1a: Single AST traversal to collect all information
	for _, file := range c.pass.Files {
		c.collectFromFile(file)
	}

	// Phase 1b: Multi-pass data flow analysis
	c.varTracker.AnalyzeDataFlow()
}

// collectFromFile collects information from a single file
func (c *DataFlowCollector) collectFromFile(file *ast.File) {
	ast.Inspect(file, func(n ast.Node) bool {
		if n == nil {
			return false
		}

		switch node := n.(type) {
		case *ast.TypeSpec:
			// Collect sensitive fields from struct definitions
			c.fieldCollector.CollectFromTypeSpec(node)

		case *ast.FuncDecl:
			// Register function definition for data flow analysis
			c.varTracker.CollectFunctionDef(node)
			c.collectFromFunction(node)
			return false // Don't traverse into function body again
		}

		return true
	})
}

// collectFromFunction collects information from within a function
func (c *DataFlowCollector) collectFromFunction(funcDecl *ast.FuncDecl) {
	// Set current function context for variable tracking
	if funcDecl.Name != nil {
		if obj := c.pass.TypesInfo.Defs[funcDecl.Name]; obj != nil {
			c.varTracker.SetCurrentFunction(obj)
		}
	}

	// Traverse function body to collect assignments, returns, and log calls
	if funcDecl.Body != nil {
		ast.Inspect(funcDecl.Body, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.AssignStmt:
				// Track variable assignments
				c.varTracker.CollectAssignment(node)

			case *ast.ReturnStmt:
				// Track return statements
				c.varTracker.CollectReturn(node)

			case *ast.CallExpr:
				// Collect log calls during traversal (single-pass optimization)
				if c.logDetector.IsLogCall(node) {
					c.logCalls = append(c.logCalls, node)
				}
			}
			return true
		})
	}

	// Reset current function context
	c.varTracker.SetCurrentFunction(nil)
}

// Analyze processes all collected log calls and returns findings
// This method implements Phase 2 of the Two-Phase Analysis Pattern
// Renamed from AnalyzeAndReport - reporting is now caller's responsibility
func (c *DataFlowCollector) Analyze() []Finding {
	// Re-initialize detector with updated sensitive fields (after collection is complete)
	c.detector = NewDetector(c.pass, c.fieldCollector.GetSensitiveFields(), c.varTracker)

	// Collect all findings from log calls
	var allFindings []Finding

	// Process all collected log calls
	for _, call := range c.logCalls {
		// Inspect arguments for sensitive data
		for _, arg := range call.Args {
			findings := c.detector.CheckArgForSensitiveData(arg)
			allFindings = append(allFindings, findings...)
		}
	}

	return allFindings
}

// Legacy API methods for backward compatibility

// GetSensitiveFields returns the collected sensitive fields
func (c *DataFlowCollector) GetSensitiveFields() map[sensitiveField]bool {
	return c.fieldCollector.GetSensitiveFields()
}

// GetSensitiveVars returns the collected sensitive variables
func (c *DataFlowCollector) GetSensitiveVars() map[*types.Var]SensitiveSource {
	return c.varTracker.GetSensitiveVars()
}

// IsSensitiveVar checks if a variable is sensitive
func (c *DataFlowCollector) IsSensitiveVar(obj types.Object) (SensitiveSource, bool) {
	return c.varTracker.IsSensitiveVar(obj)
}

// IsSensitiveCall checks if a function call returns sensitive data
func (c *DataFlowCollector) IsSensitiveCall(call *ast.CallExpr) (SensitiveSource, bool) {
	return c.varTracker.IsSensitiveCall(call)
}

// CheckArgForSensitiveData checks if an argument contains sensitive data (legacy)
// Deprecated: This method is maintained for backward compatibility only.
// Use Analyze() instead which returns findings for the caller to report.
func (c *DataFlowCollector) CheckArgForSensitiveData(arg ast.Expr) []Finding {
	return c.detector.CheckArgForSensitiveData(arg)
}
