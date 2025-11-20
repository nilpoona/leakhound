package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"go/token"
	"os"
	"path/filepath"

	"github.com/nilpoona/leakhound"
	"github.com/nilpoona/leakhound/detector"
	"github.com/nilpoona/leakhound/reporter/sarif"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/singlechecker"
	"golang.org/x/tools/go/packages"
)

// findingWithFset pairs a finding with its FileSet for position information
type findingWithFset struct {
	finding detector.Finding
	fset    *token.FileSet
}

func main() {
	// Check if SARIF format is requested
	isSARIF := false
	for _, arg := range os.Args[1:] {
		if arg == "-format=sarif" || arg == "--format=sarif" {
			isSARIF = true
			break
		}
	}

	if !isSARIF {
		// Use standard singlechecker for text format
		singlechecker.Main(leakhound.Analyzer)
		return
	}

	// Custom driver for SARIF format to aggregate all results into a single document.
	// This follows the same pattern as golangci-lint and gosec:
	// 1. Load all packages
	// 2. Run analyzer on each package
	// 3. Collect all findings
	// 4. Output single SARIF document
	runSARIFMode()
}

func runSARIFMode() {
	// Get working directory for relative paths
	workDir, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to get working directory: %v\n", err)
		os.Exit(1)
	}

	// Load packages with full type information
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
			packages.NeedImports | packages.NeedTypes | packages.NeedTypesSizes |
			packages.NeedSyntax | packages.NeedTypesInfo,
		Tests: false,
		Dir:   workDir,
	}

	// Filter out the -format flag from arguments
	patterns := os.Args[1:]
	var pkgPatterns []string
	for _, arg := range patterns {
		if arg != "-format=sarif" && arg != "--format=sarif" {
			pkgPatterns = append(pkgPatterns, arg)
		}
	}

	if len(pkgPatterns) == 0 {
		fmt.Fprintln(os.Stderr, "usage: leakhound --format=sarif <package patterns>")
		os.Exit(1)
	}

	// Load only the specified packages (not dependencies)
	pkgs, err := packages.Load(cfg, pkgPatterns...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load packages: %v\n", err)
		os.Exit(1)
	}

	// Report package errors to stderr but continue analysis
	for _, pkg := range pkgs {
		for _, pkgErr := range pkg.Errors {
			fmt.Fprintf(os.Stderr, "%v\n", pkgErr)
		}
	}

	// Collect all findings across all packages
	allFindings := []findingWithFset{}

	// Run analyzer on each package
	for _, pkg := range pkgs {
		// Skip packages with type errors (e.g., import issues)
		if pkg.Types == nil || pkg.TypesInfo == nil {
			continue
		}

		pass := &analysis.Pass{
			Analyzer:  leakhound.Analyzer,
			Fset:      pkg.Fset,
			Files:     pkg.Syntax,
			Pkg:       pkg.Types,
			TypesInfo: pkg.TypesInfo,
			ResultOf:  make(map[*analysis.Analyzer]interface{}),
			Report:    func(d analysis.Diagnostic) {}, // Suppress individual reports
		}

		// Run the analyzer
		result, runErr := leakhound.Analyzer.Run(pass)
		if runErr != nil {
			fmt.Fprintf(os.Stderr, "analysis failed for %s: %v\n", pkg.PkgPath, runErr)
			continue
		}

		// Extract findings from result
		if result != nil {
			if rt, ok := result.(*leakhound.ResultType); ok {
				for _, f := range rt.Findings {
					allFindings = append(allFindings, findingWithFset{
						finding: f,
						fset:    pkg.Fset,
					})
				}
			}
		}
	}

	// Build and output single SARIF document
	doc := buildSARIFDocument(allFindings, workDir)
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(doc); err != nil {
		fmt.Fprintf(os.Stderr, "failed to encode SARIF: %v\n", err)
		os.Exit(1)
	}
}

func buildSARIFDocument(findings []findingWithFset, workDir string) *sarif.Document {
	results := make([]sarif.Result, 0, len(findings))
	for _, f := range findings {
		pos := f.fset.Position(f.finding.Pos)
		relPath := relativePath(pos.Filename, workDir)
		results = append(results, sarif.Result{
			RuleID: f.finding.RuleID,
			Message: sarif.Message{
				Text: f.finding.Message,
			},
			Locations: []sarif.Location{
				{
					PhysicalLocation: sarif.PhysicalLocation{
						ArtifactLocation: sarif.ArtifactLocation{
							URI:       relPath,
							URIBaseID: "%SRCROOT%",
						},
						Region: sarif.Region{
							StartLine:   pos.Line,
							StartColumn: pos.Column,
						},
					},
				},
			},
			Level:               "error",
			PartialFingerprints: buildFingerprints(relPath, pos.Line, f.finding.RuleID),
		})
	}

	return &sarif.Document{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs: []sarif.Run{
			{
				Tool:              buildTool(),
				Results:           results,
				AutomationDetails: buildAutomationDetails(),
			},
		},
	}
}

func buildAutomationDetails() *sarif.AutomationDetails {
	return &sarif.AutomationDetails{
		ID: "leakhound/analysis",
	}
}

func buildFingerprints(filePath string, line int, ruleID string) map[string]string {
	// Create a stable fingerprint based on file path, line number, and rule ID
	// This ensures the same issue at the same location gets the same fingerprint
	fingerprint := fmt.Sprintf("%s:%d:%s", filePath, line, ruleID)
	hash := sha256.Sum256([]byte(fingerprint))
	primaryLocationHash := fmt.Sprintf("%x", hash[:16]) // Use first 16 bytes

	return map[string]string{
		"primaryLocationLineHash": primaryLocationHash,
	}
}

func buildTool() sarif.Tool {
	version := sarif.Version
	if version == "" {
		version = "dev"
	}

	return sarif.Tool{
		Driver: sarif.Driver{
			Name:            "leakhound",
			FullName:        "LeakHound Sensitive Data Detector",
			InformationURI:  "https://github.com/nilpoona/leakhound",
			Version:         version,
			SemanticVersion: version,
			Rules:           buildRules(),
		},
	}
}

func buildRules() []sarif.ReportingDescriptor {
	return []sarif.ReportingDescriptor{
		{
			ID:   "sensitive-var",
			Name: "SensitiveVariableLogged",
			ShortDescription: sarif.MessageString{
				Text: "Variable containing sensitive data is logged",
			},
			FullDescription: sarif.MessageString{
				Text: "A variable that contains data from a field tagged with sensitive:\"true\" is passed to a logging function.",
			},
			Help: sarif.MessageString{
				Text: "Avoid logging variables that contain sensitive information. Consider redacting or removing the sensitive data before logging.",
			},
			DefaultConfiguration: sarif.Configuration{
				Level: "error",
			},
		},
		{
			ID:   "sensitive-call",
			Name: "SensitiveFunctionCallLogged",
			ShortDescription: sarif.MessageString{
				Text: "Function call returning sensitive data is logged",
			},
			FullDescription: sarif.MessageString{
				Text: "A function call that returns sensitive data (from a field tagged with sensitive:\"true\") is passed to a logging function.",
			},
			Help: sarif.MessageString{
				Text: "Avoid logging function return values that contain sensitive information. Store the result in a variable and redact sensitive fields before logging.",
			},
			DefaultConfiguration: sarif.Configuration{
				Level: "error",
			},
		},
		{
			ID:   "sensitive-struct",
			Name: "SensitiveStructLogged",
			ShortDescription: sarif.MessageString{
				Text: "Struct containing sensitive fields is logged",
			},
			FullDescription: sarif.MessageString{
				Text: "An entire struct that contains fields tagged with sensitive:\"true\" is passed to a logging function.",
			},
			Help: sarif.MessageString{
				Text: "Avoid logging entire structs that contain sensitive fields. Log only the non-sensitive fields individually.",
			},
			DefaultConfiguration: sarif.Configuration{
				Level: "error",
			},
		},
		{
			ID:   "sensitive-field",
			Name: "SensitiveFieldLogged",
			ShortDescription: sarif.MessageString{
				Text: "Sensitive struct field is logged",
			},
			FullDescription: sarif.MessageString{
				Text: "A struct field tagged with sensitive:\"true\" is directly accessed and passed to a logging function.",
			},
			Help: sarif.MessageString{
				Text: "Avoid logging fields marked as sensitive. Remove the field from the log call or redact its value.",
			},
			DefaultConfiguration: sarif.Configuration{
				Level: "error",
			},
		},
	}
}

func relativePath(absPath, workDir string) string {
	// Convert absolute path to relative from workDir
	rel, err := filepath.Rel(workDir, absPath)
	if err != nil {
		// Fallback to absolute path if relative conversion fails
		return absPath
	}
	// Normalize path separators for cross-platform compatibility
	return filepath.ToSlash(rel)
}
