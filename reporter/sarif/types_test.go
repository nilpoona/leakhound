package sarif

import (
	"reflect"
	"testing"

	"github.com/nilpoona/leakhound/detector"
)

func TestBuildRules(t *testing.T) {
	t.Parallel()

	rules := BuildRules()

	// Test basic properties
	if len(rules) != 6 {
		t.Fatalf("BuildRules() returned %d rules, want 6", len(rules))
	}

	// Expected rule definitions
	expectedRules := []ReportingDescriptor{
		{
			ID:   "LH0001",
			Name: "SensitiveVariableLogged",
			ShortDescription: MessageString{
				Text: "Variable containing sensitive data is logged",
			},
			FullDescription: MessageString{
				Text: "A variable that contains data from a field tagged with sensitive:\"true\" is passed to a logging function.",
			},
			Help: MessageString{
				Text: "Avoid logging variables that contain sensitive information. Consider redacting or removing the sensitive data before logging.",
			},
			HelpURI: "https://github.com/nilpoona/leakhound#LH0001",
			DefaultConfiguration: Configuration{
				Level: "error",
			},
		},
		{
			ID:   "LH0002",
			Name: "SensitiveFunctionCallLogged",
			ShortDescription: MessageString{
				Text: "Function call returning sensitive data is logged",
			},
			FullDescription: MessageString{
				Text: "A function call that returns sensitive data (from a field tagged with sensitive:\"true\") is passed to a logging function.",
			},
			Help: MessageString{
				Text: "Avoid logging function return values that contain sensitive information. Store the result in a variable and redact sensitive fields before logging.",
			},
			HelpURI: "https://github.com/nilpoona/leakhound#LH0002",
			DefaultConfiguration: Configuration{
				Level: "error",
			},
		},
		{
			ID:   "LH0003",
			Name: "SensitiveStructLogged",
			ShortDescription: MessageString{
				Text: "Struct containing sensitive fields is logged",
			},
			FullDescription: MessageString{
				Text: "An entire struct that contains fields tagged with sensitive:\"true\" is passed to a logging function.",
			},
			Help: MessageString{
				Text: "Avoid logging entire structs that contain sensitive fields. Log only the non-sensitive fields individually.",
			},
			HelpURI: "https://github.com/nilpoona/leakhound#LH0003",
			DefaultConfiguration: Configuration{
				Level: "error",
			},
		},
		{
			ID:   "LH0004",
			Name: "SensitiveFieldLogged",
			ShortDescription: MessageString{
				Text: "Sensitive struct field is logged",
			},
			FullDescription: MessageString{
				Text: "A struct field tagged with sensitive:\"true\" is directly accessed and passed to a logging function.",
			},
			Help: MessageString{
				Text: "Avoid logging fields marked as sensitive. Remove the field from the log call or redact its value.",
			},
			HelpURI: "https://github.com/nilpoona/leakhound#LH0004",
			DefaultConfiguration: Configuration{
				Level: "error",
			},
		},
		{
			ID:   "LH0005",
			Name: "CrossPackageSensitiveReturnLogged",
			ShortDescription: MessageString{
				Text: "Cross-package function returning sensitive data is logged",
			},
			FullDescription: MessageString{
				Text: "A function defined in a different package returns data derived from a field tagged with sensitive:\"true\", and the result is passed to a logging function.",
			},
			Help: MessageString{
				Text: "Avoid logging the return value of cross-package functions that surface sensitive data. Redact or transform the value before logging.",
			},
			HelpURI: "https://github.com/nilpoona/leakhound#LH0005",
			DefaultConfiguration: Configuration{
				Level: "error",
			},
		},
		{
			ID:   "LH0006",
			Name: "CrossPackageSensitiveSink",
			ShortDescription: MessageString{
				Text: "Sensitive data flows into a logging sink in another package",
			},
			FullDescription: MessageString{
				Text: "Sensitive data (from a field tagged with sensitive:\"true\") is passed as an argument to a function in a different package whose body forwards that parameter to a logging function.",
			},
			Help: MessageString{
				Text: "Avoid passing sensitive values to cross-package functions that log their parameters. Redact upstream or switch to a non-logging API.",
			},
			HelpURI: "https://github.com/nilpoona/leakhound#LH0006",
			DefaultConfiguration: Configuration{
				Level: "error",
			},
		},
	}

	if !reflect.DeepEqual(rules, expectedRules) {
		t.Errorf("BuildRules() mismatch")
		for i := range rules {
			if !reflect.DeepEqual(rules[i], expectedRules[i]) {
				t.Errorf("Rule[%d] mismatch:\ngot:  %+v\nwant: %+v", i, rules[i], expectedRules[i])
			}
		}
	}
}

func TestBuildRules_RuleIDs(t *testing.T) {
	t.Parallel()

	rules := BuildRules()

	// Test that all rule IDs are unique
	ruleIDs := make(map[string]bool)
	for _, rule := range rules {
		if ruleIDs[rule.ID] {
			t.Errorf("Duplicate rule ID: %s", rule.ID)
		}
		ruleIDs[rule.ID] = true
	}

	// Test that all expected rule IDs are present
	expectedIDs := []string{"LH0001", "LH0002", "LH0003", "LH0004", "LH0005", "LH0006"}
	for _, expectedID := range expectedIDs {
		if !ruleIDs[expectedID] {
			t.Errorf("Missing expected rule ID: %s", expectedID)
		}
	}
}

func TestBuildRules_RuleNames(t *testing.T) {
	t.Parallel()

	rules := BuildRules()

	expectedNames := map[string]string{
		"LH0001": "SensitiveVariableLogged",
		"LH0002": "SensitiveFunctionCallLogged",
		"LH0003": "SensitiveStructLogged",
		"LH0004": "SensitiveFieldLogged",
		"LH0005": "CrossPackageSensitiveReturnLogged",
		"LH0006": "CrossPackageSensitiveSink",
	}

	for _, rule := range rules {
		expectedName, ok := expectedNames[rule.ID]
		if !ok {
			t.Errorf("Unexpected rule ID: %s", rule.ID)
			continue
		}
		if rule.Name != expectedName {
			t.Errorf("Rule %s: name = %q, want %q", rule.ID, rule.Name, expectedName)
		}
	}
}

func TestBuildRules_AllHaveRequiredFields(t *testing.T) {
	t.Parallel()

	rules := BuildRules()

	for i, rule := range rules {
		if rule.ID == "" {
			t.Errorf("Rule[%d]: ID should not be empty", i)
		}
		if rule.Name == "" {
			t.Errorf("Rule[%d]: Name should not be empty", i)
		}
		if rule.ShortDescription.Text == "" {
			t.Errorf("Rule[%d]: ShortDescription.Text should not be empty", i)
		}
		if rule.FullDescription.Text == "" {
			t.Errorf("Rule[%d]: FullDescription.Text should not be empty", i)
		}
		if rule.Help.Text == "" {
			t.Errorf("Rule[%d]: Help.Text should not be empty", i)
		}
		if rule.HelpURI == "" {
			t.Errorf("Rule[%d]: HelpURI should not be empty", i)
		}
		if rule.DefaultConfiguration.Level != "error" {
			t.Errorf("Rule[%d]: DefaultConfiguration.Level = %q, want %q",
				i, rule.DefaultConfiguration.Level, "error")
		}
	}
}

func TestBuildRules_HelpURIFormat(t *testing.T) {
	t.Parallel()

	rules := BuildRules()

	for _, rule := range rules {
		expectedURI := "https://github.com/nilpoona/leakhound#" + rule.ID
		if rule.HelpURI != expectedURI {
			t.Errorf("Rule %s: HelpURI = %q, want %q", rule.ID, rule.HelpURI, expectedURI)
		}
	}
}

func TestBuildRules_Immutability(t *testing.T) {
	t.Parallel()

	// Call BuildRules multiple times and verify they return the same result
	rules1 := BuildRules()
	rules2 := BuildRules()

	if !reflect.DeepEqual(rules1, rules2) {
		t.Error("BuildRules() should return consistent results across multiple calls")
	}
}

func TestRuleIDConstants(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		constant string
		want     string
	}{
		{
			name:     "RuleIDSensitiveVar",
			constant: RuleIDSensitiveVar,
			want:     "LH0001",
		},
		{
			name:     "RuleIDSensitiveCall",
			constant: RuleIDSensitiveCall,
			want:     "LH0002",
		},
		{
			name:     "RuleIDSensitiveStruct",
			constant: RuleIDSensitiveStruct,
			want:     "LH0003",
		},
		{
			name:     "RuleIDSensitiveField",
			constant: RuleIDSensitiveField,
			want:     "LH0004",
		},
	}

	for _, tt := range tests {
		tt := tt // capture range variable
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if tt.constant != tt.want {
				t.Errorf("%s = %q, want %q", tt.name, tt.constant, tt.want)
			}
		})
	}
}

func TestRuleIDMapping(t *testing.T) {
	t.Parallel()

	// Test that the internal mapping is consistent with ToSARIFRuleID
	tests := []struct {
		detectorID string
		sarifID    string
	}{
		{"sensitive-var", RuleIDSensitiveVar},
		{"sensitive-call", RuleIDSensitiveCall},
		{"sensitive-struct", RuleIDSensitiveStruct},
		{"sensitive-field", RuleIDSensitiveField},
	}

	for _, tt := range tests {
		tt := tt // capture range variable
		t.Run(tt.detectorID, func(t *testing.T) {
			t.Parallel()

			got := detector.ToSARIFRuleID(tt.detectorID)
			if got != tt.sarifID {
				t.Errorf("detector.ToSARIFRuleID(%q) = %q, want %q", tt.detectorID, got, tt.sarifID)
			}
		})
	}
}

func TestBuildRules_OrderConsistency(t *testing.T) {
	t.Parallel()

	rules := BuildRules()

	// Verify rules are in expected order by ID
	expectedOrder := []string{"LH0001", "LH0002", "LH0003", "LH0004"}

	for i, expectedID := range expectedOrder {
		if i >= len(rules) {
			t.Fatalf("Expected at least %d rules, got %d", i+1, len(rules))
		}
		if rules[i].ID != expectedID {
			t.Errorf("Rule[%d].ID = %q, want %q (rules should be in order)", i, rules[i].ID, expectedID)
		}
	}
}
