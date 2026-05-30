package detector

import (
	"go/ast"
	"go/types"

	"github.com/nilpoona/leakhound/config"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/packages"
)

// DataFlowCollector orchestrates data flow information collection in a single AST pass
// This implements the Two-Phase Analysis Pattern:
// - Phase 1: Collection (single AST pass)
// - Phase 2: Analysis (processes collected data)
type DataFlowCollector struct {
	pass *analysis.Pass

	// Optional whole-program context. When non-nil, the collector writes
	// shared facts (funcPkg, logCalls) into the world and tags each func
	// declaration with its owning package.
	world *WorldView
	pkg   *packages.Package

	// Component delegates
	fieldCollector *FieldCollector
	varTracker     *VarTracker
	logDetector    *LogDetector
	detector       *Detector

	// Log calls collected during traversal (for single-pass optimization)
	logCalls []*ast.CallExpr
}

// NewDataFlowCollector creates a new collector with all components initialized
func NewDataFlowCollector(pass *analysis.Pass, cfg *config.Config) *DataFlowCollector {
	fieldCollector := NewFieldCollector(pass)
	varTracker := NewVarTracker(pass, fieldCollector.GetSensitiveFields())
	logDetector := NewLogDetectorWithConfig(pass, cfg)
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

// NewDataFlowCollectorForWorld creates a collector whose facts are shared with
// a WorldView. Per-package collection writes into the world's accumulators so
// the whole-program analyzer can iterate across packages afterwards.
func NewDataFlowCollectorForWorld(pass *analysis.Pass, cfg *config.Config, world *WorldView, pkg *packages.Package) *DataFlowCollector {
	fieldCollector := NewFieldCollectorWithFields(pass, world.sensitiveFields)
	varTracker := NewVarTrackerForWorld(pass, world)
	logDetector := NewLogDetectorWithConfig(pass, cfg)
	detector := NewDetector(pass, world.sensitiveFields, varTracker)

	return &DataFlowCollector{
		pass:           pass,
		world:          world,
		pkg:            pkg,
		fieldCollector: fieldCollector,
		varTracker:     varTracker,
		logDetector:    logDetector,
		detector:       detector,
		logCalls:       make([]*ast.CallExpr, 0),
	}
}

// LogCalls returns the call expressions collected by IsLogCall during
// traversal. Whole-program mode aggregates these for the detection phase.
func (c *DataFlowCollector) LogCalls() []*ast.CallExpr { return c.logCalls }

// Pass returns the analyzer pass associated with this collector.
func (c *DataFlowCollector) Pass() *analysis.Pass { return c.pass }

// LogDetector returns the underlying log detector (used by whole-program
// collector when classifying call expressions cross-package).
func (c *DataFlowCollector) LogDetector() *LogDetector { return c.logDetector }

// VarTracker returns the underlying var tracker.
func (c *DataFlowCollector) VarTracker() *VarTracker { return c.varTracker }

// Detector returns the underlying detector.
func (c *DataFlowCollector) Detector() *Detector { return c.detector }

// Collect performs single-pass AST traversal to collect all information
// This implements Phase 1 of the Two-Phase Analysis Pattern
func (c *DataFlowCollector) Collect() {
	c.CollectFacts()
	// Phase 1b: Multi-pass data flow analysis. In whole-program mode this
	// step is run once by WholeProgramCollector AFTER every package has
	// contributed its facts, so we skip it here.
	if c.world == nil {
		c.varTracker.AnalyzeDataFlow()
	}
}

// CollectFacts runs only Phase 1a (single AST traversal) without per-package
// data flow analysis. WholeProgramCollector uses this to defer propagation
// until cross-package facts are available.
func (c *DataFlowCollector) CollectFacts() {
	for _, file := range c.pass.Files {
		c.collectFromFile(file)
	}
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
			// In whole-program mode, also register the owning package so
			// later phases can resolve cross-package callees back to their
			// AST bodies.
			if c.world != nil && node.Name != nil {
				if obj := c.pass.TypesInfo.Defs[node.Name]; obj != nil {
					c.world.RegisterFunc(obj, node, c.pkg)
				}
			}
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
