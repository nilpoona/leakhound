package detector

import (
	"go/token"
)

// sensitiveField holds information about fields with sensitive tags
type sensitiveField struct {
	typeName  string
	fieldName string
}

// SensitiveSource describes where a sensitive value came from
type SensitiveSource struct {
	FieldName string    // Original sensitive field name (e.g., "User.Password")
	Position  token.Pos // Position where the value was assigned/passed
	FlowPath  []string  // Data flow path for nested tracking
}
