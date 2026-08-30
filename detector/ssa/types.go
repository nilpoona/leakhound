package ssa

import (
	"go/token"

	"golang.org/x/tools/go/ssa"
)

// SensitiveSource represents the origin of sensitive data in SSA form.
// This is identical to detector.SensitiveSource but works with ssa.Value.
type SensitiveSource struct {
	// FieldName is the name of the sensitive struct field (e.g., "Password")
	FieldName string
	// TypeName is the name of the struct type containing the field (e.g., "User")
	TypeName string
	// Pos is the position where the sensitive data originates
	Pos token.Pos
	// FlowPath tracks how the sensitive data flows through the program
	FlowPath []string
}

// SSAAnalyzer performs data flow analysis using SSA representation.
// Unlike the AST-based analyzer, SSA provides automatic flow-sensitivity
// because each assignment creates a new ssa.Value.
type SSAAnalyzer struct {
	// prog is the SSA program being analyzed
	prog *ssa.Program

	// sensitiveValues maps SSA values to their sensitivity information
	// Key: ssa.Value (each value is defined exactly once in SSA)
	// Value: SensitiveSource (origin of sensitivity)
	sensitiveValues map[ssa.Value]*SensitiveSource

	// sensitiveFields tracks which struct fields are tagged sensitive:"true"
	// This is shared with the AST-based FieldCollector
	sensitiveFields map[sensitiveField]bool

	// sensitiveFuncs tracks functions that return sensitive data
	sensitiveFuncs map[*ssa.Function]bool

	// findings collects all detected sensitive data leaks
	findings []*Finding

	// fset is the file set for position information
	fset *token.FileSet
}

// sensitiveField represents a struct field marked as sensitive.
type sensitiveField struct {
	typeName  string
	fieldName string
}

// NewSSAAnalyzer creates a new SSA-based data flow analyzer.
func NewSSAAnalyzer(prog *ssa.Program, fset *token.FileSet) *SSAAnalyzer {
	return &SSAAnalyzer{
		prog:            prog,
		sensitiveValues: make(map[ssa.Value]*SensitiveSource),
		sensitiveFields: make(map[sensitiveField]bool),
		sensitiveFuncs:  make(map[*ssa.Function]bool),
		findings:        make([]*Finding, 0),
		fset:            fset,
	}
}

// IsSensitive checks if an SSA value is sensitive.
func (sa *SSAAnalyzer) IsSensitive(val ssa.Value) bool {
	_, ok := sa.sensitiveValues[val]
	return ok
}

// GetSource returns the sensitivity source for an SSA value.
func (sa *SSAAnalyzer) GetSource(val ssa.Value) *SensitiveSource {
	return sa.sensitiveValues[val]
}

// MarkSensitive marks an SSA value as sensitive with the given source.
func (sa *SSAAnalyzer) MarkSensitive(val ssa.Value, source *SensitiveSource) {
	sa.sensitiveValues[val] = source
}

// Finding represents a detected sensitive data leak in SSA analysis.
// This will be converted to detector.Finding for reporting.
type Finding struct {
	// Pos is the position of the leak
	Pos token.Pos
	// Message describes the leak
	Message string
	// RuleID identifies the type of violation
	RuleID string
	// Source is the origin of the sensitive data
	Source *SensitiveSource
}

// GetFindings returns all detected findings.
func (sa *SSAAnalyzer) GetFindings() []*Finding {
	return sa.findings
}

// addFinding adds a new finding to the results.
// Duplicate findings (same position and rule ID) are not added.
func (sa *SSAAnalyzer) addFinding(pos token.Pos, message, ruleID string, source *SensitiveSource) {
	// Check for duplicate
	for _, existing := range sa.findings {
		if existing.Pos == pos && existing.RuleID == ruleID {
			// Already reported this finding
			return
		}
	}

	sa.findings = append(sa.findings, &Finding{
		Pos:     pos,
		Message: message,
		RuleID:  ruleID,
		Source:  source,
	})
}

// DebugSensitiveFieldsCount returns the number of sensitive fields collected.
// This is for testing/debugging purposes only.
func (sa *SSAAnalyzer) DebugSensitiveFieldsCount() int {
	return len(sa.sensitiveFields)
}

// DebugSensitiveValuesCount returns the number of sensitive values tracked.
// This is for testing/debugging purposes only.
func (sa *SSAAnalyzer) DebugSensitiveValuesCount() int {
	return len(sa.sensitiveValues)
}

// DebugLogCallsCount counts how many log calls were detected.
// This is for testing/debugging purposes only.
func (sa *SSAAnalyzer) DebugLogCallsCount() int {
	count := 0
	for _, pkg := range sa.prog.AllPackages() {
		for _, member := range pkg.Members {
			if fn, ok := member.(*ssa.Function); ok && fn.Blocks != nil {
				for _, block := range fn.Blocks {
					for _, instr := range block.Instrs {
						if call, ok := instr.(*ssa.Call); ok {
							if sa.isLogCall(call) {
								count++
							}
						}
					}
				}
			}
		}
	}
	return count
}

// isLogCall checks if an SSA call is to a logging function (exposed for debugging).
func (sa *SSAAnalyzer) isLogCall(call *ssa.Call) bool {
	callee := call.Call.StaticCallee()
	if callee == nil {
		return false
	}
	if callee.Pkg == nil {
		return false
	}
	pkgPath := callee.Pkg.Pkg.Path()
	funcName := callee.Name()

	if pkgPath == "log/slog" {
		return funcName == "Info" || funcName == "Debug" || funcName == "Warn" ||
			funcName == "Error" || funcName == "InfoContext" || funcName == "DebugContext" ||
			funcName == "WarnContext" || funcName == "ErrorContext"
	}
	if pkgPath == "log" {
		return funcName == "Print" || funcName == "Printf" || funcName == "Println" ||
			funcName == "Fatal" || funcName == "Fatalf" || funcName == "Fatalln" ||
			funcName == "Panic" || funcName == "Panicf" || funcName == "Panicln"
	}
	if pkgPath == "fmt" {
		return funcName == "Print" || funcName == "Printf" || funcName == "Println" ||
			funcName == "Sprint" || funcName == "Sprintf" || funcName == "Sprintln"
	}
	return false
}
