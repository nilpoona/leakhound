package detector

import (
	"go/token"
	"go/types"
)

// sensitiveField holds information about fields with sensitive tags
type sensitiveField struct {
	typeName  string
	fieldName string
}

// sensitiveReturnKey identifies a specific return position of a function.
// Used to track multi-value returns like (string, error) where only position 0 is sensitive.
type sensitiveReturnKey struct {
	funcObj types.Object
	index   int
}

// SensitiveSource describes where a sensitive value came from
type SensitiveSource struct {
	FieldName string    // Original sensitive field name (e.g., "User.Password")
	Position  token.Pos // Position where the value was assigned/passed
	FlowPath  []string  // Data flow path for nested tracking
}
