package leakhound

import (
	"go/ast"
	"go/types"
	"strings"

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

		if !isSlogCall(call, pass) {
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

// isSlogCall checks if this is a log function call from the slog package
func isSlogCall(call *ast.CallExpr, pass *analysis.Pass) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}

	// Use type information to accurately verify if it's the slog package
	obj := pass.TypesInfo.Uses[sel.Sel]
	if obj == nil {
		return false
	}

	fn, ok := obj.(*types.Func)
	if !ok {
		return false
	}

	pkg := fn.Pkg()
	if pkg == nil || pkg.Path() != "log/slog" {
		return false
	}

	// Check log function name
	funcName := sel.Sel.Name
	return funcName == "Info" || funcName == "Error" ||
		funcName == "Warn" || funcName == "Debug" ||
		funcName == "InfoContext" || funcName == "ErrorContext" ||
		funcName == "WarnContext" || funcName == "DebugContext" ||
		funcName == "Log" || funcName == "LogAttrs"
}

// checkArgForSensitiveFields checks if the argument contains sensitive fields
func checkArgForSensitiveFields(pass *analysis.Pass, arg ast.Expr, sensitiveFields map[sensitiveField]bool) {
	ast.Inspect(arg, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}

		// Get the type of field access
		tv, ok := pass.TypesInfo.Types[sel.X]
		if !ok {
			return true
		}

		// Get element type if it's a pointer type
		typ := tv.Type
		if ptr, ok := typ.(*types.Pointer); ok {
			typ = ptr.Elem()
		}

		// Case for struct type
		named, ok := typ.(*types.Named)
		if !ok {
			return true
		}

		typeName := named.Obj().Name()
		fieldName := sel.Sel.Name

		// Check if it has a sensitive tag
		sf := sensitiveField{
			typeName:  typeName,
			fieldName: fieldName,
		}

		if sensitiveFields[sf] {
			pass.Reportf(sel.Pos(),
				"sensitive field '%s.%s' should not be logged (tagged with sensitive:\"true\")",
				typeName, fieldName)
		}

		return true
	})
}
