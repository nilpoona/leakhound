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
	version string // Tool version
}

// Version of leakhound (exported for backward compatibility and build-time injection)
var Version = "0.0.8"

// NewReporter creates a SARIF reporter
func NewReporter(pass *analysis.Pass, writer io.Writer, workDir string) *Reporter {
	return &Reporter{
		pass:    pass,
		writer:  writer,
		workDir: workDir,
		version: Version, // Capture version at creation time
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
		Schema:  "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
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
	version := r.version
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

// buildRules returns all rule descriptors using shared definitions
func (r *Reporter) buildRules() []ReportingDescriptor {
	return BuildRules()
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
	sarifRuleID := ToSARIFRuleID(f.RuleID)

	return Result{
		RuleID: sarifRuleID,
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
		PartialFingerprints: r.buildFingerprints(relPath, pos.Line, sarifRuleID),
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
