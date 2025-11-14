package detector

import "go/token"

// Finding represents a detected sensitive data leak
type Finding struct {
	Pos     token.Pos
	Message string
	RuleID  string
}
