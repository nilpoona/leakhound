package detector

import "testing"

func TestToSARIFRuleID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		detRuleID string
		want      string
	}{
		{"sensitive-var → LH0001", RuleIDSensitiveVar, "LH0001"},
		{"sensitive-call → LH0002", RuleIDSensitiveCall, "LH0002"},
		{"sensitive-struct → LH0003", RuleIDSensitiveStruct, "LH0003"},
		{"sensitive-field → LH0004", RuleIDSensitiveField, "LH0004"},
		{"unknown returns as-is", "unknown-rule", "unknown-rule"},
		{"empty returns as-is", "", ""},
		{"partial match returns as-is", "sensitive-variable", "sensitive-variable"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := ToSARIFRuleID(tt.detRuleID)
			if got != tt.want {
				t.Errorf("ToSARIFRuleID(%q) = %q, want %q", tt.detRuleID, got, tt.want)
			}
		})
	}
}

func TestFinding_SARIFRuleID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		ruleID string
		want   string
	}{
		{RuleIDSensitiveVar, "LH0001"},
		{RuleIDSensitiveCall, "LH0002"},
		{RuleIDSensitiveStruct, "LH0003"},
		{RuleIDSensitiveField, "LH0004"},
		{"unknown", "unknown"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.ruleID, func(t *testing.T) {
			t.Parallel()
			f := Finding{RuleID: tt.ruleID}
			if got := f.SARIFRuleID(); got != tt.want {
				t.Errorf("Finding{RuleID:%q}.SARIFRuleID() = %q, want %q", tt.ruleID, got, tt.want)
			}
		})
	}
}
