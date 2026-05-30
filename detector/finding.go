package detector

import "go/token"

// Finding represents a detected sensitive data leak
type Finding struct {
	Pos             token.Pos
	Message         string
	RuleID          string
	Suppressed      bool   // true if suppressed by inline comment or config
	SuppressionKind string // "inSource" (inline comment) or "external" (config file)
}

// ruleIDToSARIF maps detector rule IDs to SARIF conventional format.
var ruleIDToSARIF = map[string]string{
	RuleIDSensitiveVar:            "LH0001",
	RuleIDSensitiveCall:           "LH0002",
	RuleIDSensitiveStruct:         "LH0003",
	RuleIDSensitiveField:          "LH0004",
	RuleIDCrossPkgSensitiveReturn: "LH0005",
	RuleIDCrossPkgSensitiveSink:   "LH0006",
}

// ToSARIFRuleID converts a detector rule ID to SARIF format (e.g. "sensitive-var" → "LH0001").
// Returns the original ID unchanged if no mapping is defined.
func ToSARIFRuleID(ruleID string) string {
	if sarifID, ok := ruleIDToSARIF[ruleID]; ok {
		return sarifID
	}
	return ruleID
}

// SARIFRuleID returns the SARIF rule ID for this finding.
func (f Finding) SARIFRuleID() string {
	return ToSARIFRuleID(f.RuleID)
}
