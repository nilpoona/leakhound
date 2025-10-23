package leakhound

import (
	"go/ast"
	"go/types"
	"strings"

	"github.com/nilpoona/leakhound/slogchecker"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
)

const Doc = `leakhound detects whether fields tagged with sensitive are being output in slog.

It reports an error when struct fields tagged with sensitive:"true" are passed to 
logging functions in the log/slog package.

Example:
	type User struct {
		Name     string
		Password string sensitive:"true"
	}

	// NG: Password field is being output to logs
	slog.Info("user", "password", user.Password)
`

var Analyzer = &analysis.Analyzer{
	Name:     "leakhound",
	Doc:      Doc,
	Run:      run,
	Requires: []*analysis.Analyzer{inspect.Analyzer},
}

// sensitiveField holds information about fields with sensitive tags
type sensitiveField struct {
	typeName  string
	fieldName string
}

func run(pass *analysis.Pass) (interface{}, error) {
	inspect := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)

	// Step 1: Collect fields with sensitive tags
	sensitiveFields := collectSensitiveFields(pass)

	// Step 2: Inspect slog calls
	nodeFilter := []ast.Node{
		(*ast.CallExpr)(nil),
	}

	inspect.Preorder(nodeFilter, func(n ast.Node) {
		call := n.(*ast.CallExpr)

		if !slogchecker.IsSlogCall(call, pass) {
			return
		}

		// Inspect arguments
		for _, arg := range call.Args {
			checkArgForSensitiveFields(pass, arg, sensitiveFields)
		}
	})

	return nil, nil
}

// collectSensitiveFields collects fields with sensitive tags
func collectSensitiveFields(pass *analysis.Pass) map[sensitiveField]bool {
	fields := make(map[sensitiveField]bool)

	for _, file := range pass.Files {
		ast.Inspect(file, func(n ast.Node) bool {
			typeSpec, ok := n.(*ast.TypeSpec)
			if !ok {
				return true
			}

			structType, ok := typeSpec.Type.(*ast.StructType)
			if !ok {
				return true
			}

			typeName := typeSpec.Name.Name

			// Check tags for each field
			for _, field := range structType.Fields.List {
				if field.Tag == nil {
					continue
				}

				tagValue := strings.Trim(field.Tag.Value, "`")
				if !hasSensitiveTag(tagValue) {
					continue
				}

				// Record fields with sensitive tags
				for _, name := range field.Names {
					fields[sensitiveField{
						typeName:  typeName,
						fieldName: name.Name,
					}] = true
				}
			}

			return true
		})
	}

	return fields
}

// hasSensitiveTag checks if the tag string contains sensitive:"true"
func hasSensitiveTag(tag string) bool {
	// Support both sensitive:"true" and sensitive:\"true\" formats
	return strings.Contains(tag, `sensitive:"true"`) ||
		strings.Contains(tag, `sensitive:\"true\"`)
}

// hasAnySensitiveFields checks if a struct type has any fields with sensitive tags
func hasAnySensitiveFields(typeName string, sensitiveFields map[sensitiveField]bool) bool {
	for sf := range sensitiveFields {
		if sf.typeName == typeName {
			return true
		}
	}
	return false
}

// hasAnySensitiveFieldsFromType checks if a struct type has any sensitive fields using type info
func hasAnySensitiveFieldsFromType(pass *analysis.Pass, named *types.Named) bool {
	return checkStructForSensitiveFields(pass, named)
}

// checkArgForSensitiveFields checks if the argument contains sensitive fields
func checkArgForSensitiveFields(pass *analysis.Pass, arg ast.Expr, sensitiveFields map[sensitiveField]bool) {
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
				checkArgForSensitiveFields(pass, callArg, sensitiveFields)
			}
			return false // Don't traverse into call expr again
		}
		return true
	})
}

// checkFieldAccess checks if a selector expression accesses a sensitive field
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

// checkSensitiveFieldFromTypeInfo checks if a field has sensitive tag using type information
func checkSensitiveFieldFromTypeInfo(pass *analysis.Pass, named *types.Named, fieldName string) bool {
	// Get the underlying struct type
	underlying, ok := named.Underlying().(*types.Struct)
	if !ok {
		return false
	}

	// Find the field
	for i := 0; i < underlying.NumFields(); i++ {
		field := underlying.Field(i)
		if field.Name() == fieldName {
			// Get the struct tag
			tag := underlying.Tag(i)
			return hasSensitiveTag(tag)
		}
	}

	return false
}

// checkStructForSensitiveFields checks if a struct type has any sensitive fields using type info
func checkStructForSensitiveFields(pass *analysis.Pass, named *types.Named) bool {
	// Get the underlying struct type
	underlying, ok := named.Underlying().(*types.Struct)
	if !ok {
		return false
	}

	// Check all fields for sensitive tags
	for i := 0; i < underlying.NumFields(); i++ {
		tag := underlying.Tag(i)
		if hasSensitiveTag(tag) {
			return true
		}
	}

	return false
}
