package detector

import (
	"go/ast"
	"go/types"
	"strings"

	"golang.org/x/tools/go/analysis"
)

// FieldCollector collects fields with sensitive tags from struct definitions
type FieldCollector struct {
	pass            *analysis.Pass
	sensitiveFields map[sensitiveField]bool
}

// NewFieldCollector creates a new FieldCollector
func NewFieldCollector(pass *analysis.Pass) *FieldCollector {
	return &FieldCollector{
		pass:            pass,
		sensitiveFields: make(map[sensitiveField]bool),
	}
}

// CollectFromTypeSpec collects sensitive fields from a TypeSpec node
func (fc *FieldCollector) CollectFromTypeSpec(typeSpec *ast.TypeSpec) {
	structType, ok := typeSpec.Type.(*ast.StructType)
	if !ok {
		return
	}

	typeName := typeSpec.Name.Name

	for _, field := range structType.Fields.List {
		if field.Tag == nil {
			continue
		}

		tagValue := strings.Trim(field.Tag.Value, "`")
		if !HasSensitiveTag(tagValue) {
			continue
		}

		for _, name := range field.Names {
			fc.sensitiveFields[sensitiveField{
				typeName:  typeName,
				fieldName: name.Name,
			}] = true
		}
	}
}

// GetSensitiveFields returns all collected sensitive fields
func (fc *FieldCollector) GetSensitiveFields() map[sensitiveField]bool {
	return fc.sensitiveFields
}

// HasSensitiveTag checks if the tag string contains sensitive:"true"
func HasSensitiveTag(tag string) bool {
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
// This also checks for embedded structs with sensitive fields
func hasAnySensitiveFieldsFromType(pass *analysis.Pass, named *types.Named) bool {
	return checkStructForSensitiveFields(pass, named, make(map[string]bool))
}

// checkStructForSensitiveFields checks if a struct type has any sensitive fields using type info
// This recursively checks embedded structs as well
func checkStructForSensitiveFields(pass *analysis.Pass, named *types.Named, visited map[string]bool) bool {
	// Get the underlying struct type
	underlying, ok := named.Underlying().(*types.Struct)
	if !ok {
		return false
	}

	// Prevent infinite recursion for circular struct references
	typeName := named.Obj().Name()
	if visited[typeName] {
		return false
	}
	visited[typeName] = true

	// Check all fields for sensitive tags
	for i := 0; i < underlying.NumFields(); i++ {
		field := underlying.Field(i)
		tag := underlying.Tag(i)

		// Check if this field has a sensitive tag
		if HasSensitiveTag(tag) {
			return true
		}

		// Check if this is an embedded struct with sensitive fields
		if field.Embedded() {
			fieldType := field.Type()

			// Handle pointer to embedded struct
			if ptr, ok := fieldType.(*types.Pointer); ok {
				fieldType = ptr.Elem()
			}

			// Check if the embedded type is a named struct
			if namedType, ok := fieldType.(*types.Named); ok {
				if checkStructForSensitiveFields(pass, namedType, visited) {
					return true
				}
			}
		}
	}

	return false
}

// checkSensitiveFieldFromTypeInfo checks if a field has sensitive tag using type information
// This also checks embedded structs for the field
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
			return HasSensitiveTag(tag)
		}

		// Check embedded structs for the field
		if field.Embedded() {
			fieldType := field.Type()

			// Handle pointer to embedded struct
			if ptr, ok := fieldType.(*types.Pointer); ok {
				fieldType = ptr.Elem()
			}

			// Check if the embedded type is a named struct
			if namedType, ok := fieldType.(*types.Named); ok {
				if checkSensitiveFieldFromTypeInfo(pass, namedType, fieldName) {
					return true
				}
			}
		}
	}

	return false
}

// CollectSensitiveFields collects fields with sensitive tags (legacy two-pass approach)
// This function is maintained for backward compatibility
func CollectSensitiveFields(pass *analysis.Pass) map[sensitiveField]bool {
	fields := make(map[sensitiveField]bool)
	sensitiveTypes := make(map[string]bool)

	// First pass: collect directly sensitive fields
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
				if !HasSensitiveTag(tagValue) {
					continue
				}

				// Record fields with sensitive tags
				for _, name := range field.Names {
					fields[sensitiveField{
						typeName:  typeName,
						fieldName: name.Name,
					}] = true
				}

				// Mark this type as containing sensitive fields
				sensitiveTypes[typeName] = true
			}

			return true
		})
	}

	// Second pass: collect structs with embedded sensitive types
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

			// Check for embedded structs with sensitive fields
			for _, field := range structType.Fields.List {
				// Embedded struct has no field name
				if len(field.Names) == 0 {
					// Get the embedded type name
					if ident, ok := field.Type.(*ast.Ident); ok {
						embeddedTypeName := ident.Name
						// If the embedded type contains sensitive fields, mark parent as sensitive
						if sensitiveTypes[embeddedTypeName] {
							sensitiveTypes[typeName] = true
						}
					}
				}
			}

			return true
		})
	}

	return fields
}
