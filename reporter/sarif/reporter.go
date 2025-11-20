package sarif

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"

	"github.com/nilpoona/leakhound/detector"
	"golang.org/x/tools/go/analysis"
)

// Reporter builds and outputs SARIF documents
type Reporter struct {
	pass    *analysis.Pass
	writer  io.Writer
	workDir string // Repository root for relative paths
}

// Version of leakhound
var Version = "0.0.8"

// NewReporter creates a SARIF reporter
func NewReporter(pass *analysis.Pass, writer io.Writer, workDir string) *Reporter {
	return &Reporter{
		pass:    pass,
		writer:  writer,
		workDir: workDir,
	}
}

// Report converts findings to SARIF and writes to output
func (r *Reporter) Report(findings []detector.Finding) error {
	doc := r.buildDocument(findings)
	return r.writeDocument(doc)
}

// buildDocument creates SARIF document from findings
func (r *Reporter) buildDocument(findings []detector.Finding) *Document {
	return &Document{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs: []Run{
			{
				Tool:              r.buildTool(),
				Results:           r.buildResults(findings),
				AutomationDetails: r.buildAutomationDetails(),
			},
		},
	}
}

// buildAutomationDetails creates automation details for the run
func (r *Reporter) buildAutomationDetails() *AutomationDetails {
	return &AutomationDetails{
		ID: "leakhound/analysis",
	}
}

// buildTool creates tool descriptor
func (r *Reporter) buildTool() Tool {
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
func (r *Reporter) buildRules() []ReportingDescriptor {
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

// buildResults converts findings to SARIF results
func (r *Reporter) buildResults(findings []detector.Finding) []Result {
	results := make([]Result, 0, len(findings))
	for _, f := range findings {
		results = append(results, r.buildResult(f))
	}
	return results
}

// buildResult converts a single finding to SARIF result
func (r *Reporter) buildResult(f detector.Finding) Result {
	pos := r.pass.Fset.Position(f.Pos)
	relPath := r.relativePath(pos.Filename)

	return Result{
		RuleID: f.RuleID,
		Message: Message{
			Text: f.Message,
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
		PartialFingerprints: r.buildFingerprints(relPath, pos.Line, f.RuleID),
	}
}

// buildFingerprints generates stable fingerprints for result matching
func (r *Reporter) buildFingerprints(filePath string, line int, ruleID string) map[string]string {
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
func (r *Reporter) relativePath(absPath string) string {
	relPath, err := filepath.Rel(r.workDir, absPath)
	if err != nil {
		// Fallback to absolute path if relative conversion fails
		return absPath
	}

	// Normalize path separators for cross-platform compatibility
	return filepath.ToSlash(relPath)
}

// writeDocument serializes and writes SARIF JSON
func (r *Reporter) writeDocument(doc *Document) error {
	encoder := json.NewEncoder(r.writer)
	encoder.SetIndent("", "  ") // Pretty print
	return encoder.Encode(doc)
}
