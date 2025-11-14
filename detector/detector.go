package detector

import (
	"fmt"
	"go/ast"
	"go/types"

	"golang.org/x/tools/go/analysis"
)

// Rule ID constants for different types of findings
const (
	RuleIDSensitiveVar    = "sensitive-var"
	RuleIDSensitiveCall   = "sensitive-call"
	RuleIDSensitiveStruct = "sensitive-struct"
	RuleIDSensitiveField  = "sensitive-field"
)

// Detector handles detection of sensitive data leaks
type Detector struct {
	pass            *analysis.Pass
	sensitiveFields map[sensitiveField]bool
	varTracker      *VarTracker
}

// NewDetector creates a new Detector
func NewDetector(pass *analysis.Pass, sensitiveFields map[sensitiveField]bool, varTracker *VarTracker) *Detector {
	return &Detector{
		pass:            pass,
		sensitiveFields: sensitiveFields,
		varTracker:      varTracker,
	}
}

// CheckArgForSensitiveData checks if an argument contains sensitive data
// This includes: direct field access, variables, function calls, and entire structs
// Returns a slice of Finding objects for each detected issue
func (d *Detector) CheckArgForSensitiveData(arg ast.Expr) []Finding {
	var findings []Finding

	// First check if the argument is a sensitive variable
	if ident, ok := arg.(*ast.Ident); ok {
		if obj := d.pass.TypesInfo.Uses[ident]; obj != nil {
			if source, found := d.varTracker.IsSensitiveVar(obj); found {
				findings = append(findings, Finding{
					Pos: arg.Pos(),
					Message: fmt.Sprintf(
						"variable %q contains sensitive field %q (tagged with sensitive:\"true\")",
						ident.Name, source.FieldName),
					RuleID: RuleIDSensitiveVar,
				})
				return findings
			}
		}
	}

	// Check if it's a function call that returns sensitive data
	if call, ok := arg.(*ast.CallExpr); ok {
		if source, found := d.varTracker.IsSensitiveCall(call); found {
			findings = append(findings, Finding{
				Pos: arg.Pos(),
				Message: fmt.Sprintf(
					"function call returns sensitive field %q (tagged with sensitive:\"true\")",
					source.FieldName),
				RuleID: RuleIDSensitiveCall,
			})
			return findings
		}
	}

	// Check if the argument itself is a struct with sensitive fields
	if tv, ok := d.pass.TypesInfo.Types[arg]; ok {
		typ := tv.Type
		// Get element type if it's a pointer type
		if ptr, ok := typ.(*types.Pointer); ok {
			typ = ptr.Elem()
		}

		// Check if the entire struct has sensitive fields
		if named, ok := typ.(*types.Named); ok {
			// Add nil check for named type object to handle build constraint issues
			obj := named.Obj()
			if obj == nil {
				return findings
			}
			typeName := obj.Name()

			// Check local cache first
			if hasAnySensitiveFields(typeName, d.sensitiveFields) {
				findings = append(findings, Finding{
					Pos: arg.Pos(),
					Message: fmt.Sprintf(
						"struct '%s' contains sensitive fields and should not be logged entirely",
						typeName),
					RuleID: RuleIDSensitiveStruct,
				})
				return findings
			}

			// If not found in local cache, check using type info
			if hasAnySensitiveFieldsFromType(d.pass, named) {
				findings = append(findings, Finding{
					Pos: arg.Pos(),
					Message: fmt.Sprintf(
						"struct '%s' contains sensitive fields and should not be logged entirely",
						typeName),
					RuleID: RuleIDSensitiveStruct,
				})
				return findings
			}
		}
	}

	// Check for field access within the argument (including nested function calls)
	ast.Inspect(arg, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.SelectorExpr:
			// Handle field access like config.Secret
			if finding := d.checkFieldAccess(node); finding != nil {
				findings = append(findings, *finding)
			}
		case *ast.CallExpr:
			// Handle function calls like slog.Any("data", config)
			for _, callArg := range node.Args {
				findings = append(findings, d.CheckArgForSensitiveData(callArg)...)
			}
			return false // Don't traverse into call expr again
		}
		return true
	})

	return findings
}

// checkFieldAccess checks if a selector expression accesses a sensitive field
// Returns a Finding if sensitive field is detected, nil otherwise
func (d *Detector) checkFieldAccess(sel *ast.SelectorExpr) *Finding {
	// Get the type of field access
	tv, ok := d.pass.TypesInfo.Types[sel.X]
	if !ok {
		return nil
	}

	// Get element type if it's a pointer type
	typ := tv.Type
	if ptr, ok := typ.(*types.Pointer); ok {
		typ = ptr.Elem()
	}

	// Case for struct type
	named, ok := typ.(*types.Named)
	if !ok {
		return nil
	}

	// Add nil check for named type object to handle build constraint issues
	obj := named.Obj()
	if obj == nil {
		return nil
	}

	typeName := obj.Name()
	fieldName := sel.Sel.Name

	// First check local sensitive fields cache
	sf := sensitiveField{
		typeName:  typeName,
		fieldName: fieldName,
	}

	if d.sensitiveFields[sf] {
		return &Finding{
			Pos: sel.Pos(),
			Message: fmt.Sprintf(
				"sensitive field '%s.%s' should not be logged (tagged with sensitive:\"true\")",
				typeName, fieldName),
			RuleID: RuleIDSensitiveField,
		}
	}

	// If not found in local cache, check the actual struct definition using type info
	if checkSensitiveFieldFromTypeInfo(d.pass, named, fieldName) {
		return &Finding{
			Pos: sel.Pos(),
			Message: fmt.Sprintf(
				"sensitive field '%s.%s' should not be logged (tagged with sensitive:\"true\")",
				typeName, fieldName),
			RuleID: RuleIDSensitiveField,
		}
	}

	return nil
}
