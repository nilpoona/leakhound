package sarif

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"go/token"
	"io"
	"path/filepath"

	"github.com/nilpoona/leakhound/detector"
)

// FindingWithFset pairs a finding with its FileSet for position information
type FindingWithFset struct {
	Finding detector.Finding
	Fset    *token.FileSet
}

// AggregatingReporter collects findings from multiple packages and builds a single SARIF document
type AggregatingReporter struct {
	workDir  string
	findings []FindingWithFset
}

// NewAggregatingReporter creates a new aggregating reporter for multi-package analysis
func NewAggregatingReporter(workDir string) *AggregatingReporter {
	return &AggregatingReporter{
		workDir:  workDir,
		findings: []FindingWithFset{},
	}
}

// AddFindings adds findings from a single package analysis
func (r *AggregatingReporter) AddFindings(findings []detector.Finding, fset *token.FileSet) {
	for _, f := range findings {
		r.findings = append(r.findings, FindingWithFset{
			Finding: f,
			Fset:    fset,
		})
	}
}

// Report builds and writes a single SARIF document containing all collected findings
func (r *AggregatingReporter) Report(writer io.Writer) error {
	doc := r.buildDocument()
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(doc)
}

// buildDocument creates SARIF document from all collected findings
func (r *AggregatingReporter) buildDocument() *Document {
	return &Document{
		Version: "2.1.0",
		Schema:  "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
		Runs: []Run{
			{
				Tool:              r.buildTool(),
				Results:           r.buildResults(),
				AutomationDetails: r.buildAutomationDetails(),
			},
		},
	}
}

// buildAutomationDetails creates automation details for the run
func (r *AggregatingReporter) buildAutomationDetails() *AutomationDetails {
	return &AutomationDetails{
		ID: "leakhound/analysis",
	}
}

// buildTool creates tool descriptor
func (r *AggregatingReporter) buildTool() Tool {
	version := Version
	if version == "" {
		version = "dev"
	}

	return Tool{
		Driver: Driver{
			Name:            "leakhound",
			FullName:        "LeakHound Sensitive Data Detector",
			InformationURI:  "https://github.com/nilpoona/leakhound",
			Version:         version,
			SemanticVersion: version,
			Rules:           r.buildRules(),
		},
	}
}

// buildRules defines all rule descriptors
func (r *AggregatingReporter) buildRules() []ReportingDescriptor {
	return []ReportingDescriptor{
		{
			ID:   "sensitive-var",
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
			DefaultConfiguration: Configuration{
				Level: "error",
			},
		},
		{
			ID:   "sensitive-call",
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
			DefaultConfiguration: Configuration{
				Level: "error",
			},
		},
		{
			ID:   "sensitive-struct",
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
			DefaultConfiguration: Configuration{
				Level: "error",
			},
		},
		{
			ID:   "sensitive-field",
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
			DefaultConfiguration: Configuration{
				Level: "error",
			},
		},
	}
}

// buildResults converts all findings to SARIF results
func (r *AggregatingReporter) buildResults() []Result {
	results := make([]Result, 0, len(r.findings))
	for _, f := range r.findings {
		results = append(results, r.buildResult(f))
	}
	return results
}

// buildResult converts a single finding to SARIF result
func (r *AggregatingReporter) buildResult(f FindingWithFset) Result {
	pos := f.Fset.Position(f.Finding.Pos)
	relPath := r.relativePath(pos.Filename)

	return Result{
		RuleID: f.Finding.RuleID,
		Message: Message{
			Text: f.Finding.Message,
		},
		Locations: []Location{
			{
				PhysicalLocation: PhysicalLocation{
					ArtifactLocation: ArtifactLocation{
						URI:       relPath,
						URIBaseID: "%SRCROOT%",
					},
					Region: Region{
						StartLine:   pos.Line,
						StartColumn: pos.Column,
					},
				},
			},
		},
		Level:               "error",
		PartialFingerprints: r.buildFingerprints(relPath, pos.Line, f.Finding.RuleID),
	}
}

// buildFingerprints generates stable fingerprints for result matching
func (r *AggregatingReporter) buildFingerprints(filePath string, line int, ruleID string) map[string]string {
	// Create a stable fingerprint based on file path, line number, and rule ID
	// This ensures the same issue at the same location gets the same fingerprint
	fingerprint := fmt.Sprintf("%s:%d:%s", filePath, line, ruleID)
	hash := sha256.Sum256([]byte(fingerprint))
	primaryLocationHash := fmt.Sprintf("%x", hash[:16]) // Use first 16 bytes

	return map[string]string{
		"primaryLocationLineHash": primaryLocationHash,
	}
}

// relativePath converts absolute path to relative from workDir
func (r *AggregatingReporter) relativePath(absPath string) string {
	relPath, err := filepath.Rel(r.workDir, absPath)
	if err != nil {
		// Fallback to absolute path if relative conversion fails
		return absPath
	}

	// Normalize path separators for cross-platform compatibility
	return filepath.ToSlash(relPath)
}
