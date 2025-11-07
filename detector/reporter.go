package detector

import (
	"go/ast"
	"go/types"

	"golang.org/x/tools/go/analysis"
)

// Reporter handles reporting of sensitive data leaks
type Reporter struct {
	pass            *analysis.Pass
	sensitiveFields map[sensitiveField]bool
	varTracker      *VarTracker
}

// NewReporter creates a new Reporter
func NewReporter(pass *analysis.Pass, sensitiveFields map[sensitiveField]bool, varTracker *VarTracker) *Reporter {
	return &Reporter{
		pass:            pass,
		sensitiveFields: sensitiveFields,
		varTracker:      varTracker,
	}
}

// CheckArgForSensitiveData checks if an argument contains sensitive data
// This includes: direct field access, variables, function calls, and entire structs
func (r *Reporter) CheckArgForSensitiveData(arg ast.Expr) {
	// First check if the argument is a sensitive variable or call
	if ident, ok := arg.(*ast.Ident); ok {
		if obj := r.pass.TypesInfo.Uses[ident]; obj != nil {
			if source, found := r.varTracker.IsSensitiveVar(obj); found {
				r.pass.Reportf(arg.Pos(),
					"variable %q contains sensitive field %q (tagged with sensitive:\"true\")",
					ident.Name, source.FieldName)
				return
			}
		}
	}

	// Check if it's a function call that returns sensitive data
	if call, ok := arg.(*ast.CallExpr); ok {
		if source, found := r.varTracker.IsSensitiveCall(call); found {
			r.pass.Reportf(arg.Pos(),
				"function call returns sensitive field %q (tagged with sensitive:\"true\")",
				source.FieldName)
			return
		}
	}

	// Check if the argument itself is a struct with sensitive fields
	if tv, ok := r.pass.TypesInfo.Types[arg]; ok {
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
				return
			}
			typeName := obj.Name()

			// Check local cache first
			if hasAnySensitiveFields(typeName, r.sensitiveFields) {
				r.pass.Reportf(arg.Pos(),
					"struct '%s' contains sensitive fields and should not be logged entirely",
					typeName)
				return
			}

			// If not found in local cache, check using type info
			if hasAnySensitiveFieldsFromType(r.pass, named) {
				r.pass.Reportf(arg.Pos(),
					"struct '%s' contains sensitive fields and should not be logged entirely",
					typeName)
				return
			}
		}
	}

	// Check for field access within the argument (including nested function calls)
	ast.Inspect(arg, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.SelectorExpr:
			// Handle field access like config.Secret
			r.checkFieldAccess(node)
		case *ast.CallExpr:
			// Handle function calls like slog.Any("data", config)
			for _, callArg := range node.Args {
				r.CheckArgForSensitiveData(callArg)
			}
			return false // Don't traverse into call expr again
		}
		return true
	})
}

// checkFieldAccess checks if a selector expression accesses a sensitive field
func (r *Reporter) checkFieldAccess(sel *ast.SelectorExpr) {
	// Get the type of field access
	tv, ok := r.pass.TypesInfo.Types[sel.X]
	if !ok {
		return
	}

	// Get element type if it's a pointer type
	typ := tv.Type
	if ptr, ok := typ.(*types.Pointer); ok {
		typ = ptr.Elem()
	}

	// Case for struct type
	named, ok := typ.(*types.Named)
	if !ok {
		return
	}

	// Add nil check for named type object to handle build constraint issues
	obj := named.Obj()
	if obj == nil {
		return
	}

	typeName := obj.Name()
	fieldName := sel.Sel.Name

	// First check local sensitive fields cache
	sf := sensitiveField{
		typeName:  typeName,
		fieldName: fieldName,
	}

	if r.sensitiveFields[sf] {
		r.pass.Reportf(sel.Pos(),
			"sensitive field '%s.%s' should not be logged (tagged with sensitive:\"true\")",
			typeName, fieldName)
		return
	}

	// If not found in local cache, check the actual struct definition using type info
	if checkSensitiveFieldFromTypeInfo(r.pass, named, fieldName) {
		r.pass.Reportf(sel.Pos(),
			"sensitive field '%s.%s' should not be logged (tagged with sensitive:\"true\")",
			typeName, fieldName)
	}
}

// CheckArgForSensitiveFields checks if the argument contains sensitive fields (legacy API)
// This function is maintained for backward compatibility
func CheckArgForSensitiveFields(pass *analysis.Pass, arg ast.Expr, sensitiveFields map[sensitiveField]bool) {
	// First check if the argument itself is a struct with sensitive fields
	if tv, ok := pass.TypesInfo.Types[arg]; ok {
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
				return
			}
			typeName := obj.Name()

			// Check local cache first
			if hasAnySensitiveFields(typeName, sensitiveFields) {
				pass.Reportf(arg.Pos(),
					"struct '%s' contains sensitive fields and should not be logged entirely",
					typeName)
				return
			}

			// If not found in local cache, check using type info
			if hasAnySensitiveFieldsFromType(pass, named) {
				pass.Reportf(arg.Pos(),
					"struct '%s' contains sensitive fields and should not be logged entirely",
					typeName)
				return
			}
		}
	}

	// Then check for field access within the argument (including nested function calls)
	ast.Inspect(arg, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.SelectorExpr:
			// Handle field access like config.Secret
			checkFieldAccess(pass, node, sensitiveFields)
		case *ast.CallExpr:
			// Handle function calls like slog.Any("data", config)
			for _, callArg := range node.Args {
				CheckArgForSensitiveFields(pass, callArg, sensitiveFields)
			}
			return false // Don't traverse into call expr again
		}
		return true
	})
}

// checkFieldAccess checks if a selector expression accesses a sensitive field (legacy)
func checkFieldAccess(pass *analysis.Pass, sel *ast.SelectorExpr, sensitiveFields map[sensitiveField]bool) {
	// Get the type of field access
	tv, ok := pass.TypesInfo.Types[sel.X]
	if !ok {
		return
	}

	// Get element type if it's a pointer type
	typ := tv.Type
	if ptr, ok := typ.(*types.Pointer); ok {
		typ = ptr.Elem()
	}

	// Case for struct type
	named, ok := typ.(*types.Named)
	if !ok {
		return
	}

	// Add nil check for named type object to handle build constraint issues
	obj := named.Obj()
	if obj == nil {
		return
	}

	typeName := obj.Name()
	fieldName := sel.Sel.Name

	// First check local sensitive fields cache
	sf := sensitiveField{
		typeName:  typeName,
		fieldName: fieldName,
	}

	if sensitiveFields[sf] {
		pass.Reportf(sel.Pos(),
			"sensitive field '%s.%s' should not be logged (tagged with sensitive:\"true\")",
			typeName, fieldName)
		return
	}

	// If not found in local cache, check the actual struct definition using type info
	if checkSensitiveFieldFromTypeInfo(pass, named, fieldName) {
		pass.Reportf(sel.Pos(),
			"sensitive field '%s.%s' should not be logged (tagged with sensitive:\"true\")",
			typeName, fieldName)
	}
}
