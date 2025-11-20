package main

import (
	"fmt"
	"os"

	"github.com/nilpoona/leakhound"
	"github.com/nilpoona/leakhound/reporter/sarif"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/singlechecker"
	"golang.org/x/tools/go/packages"
)

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

	// Create aggregating reporter for collecting findings from all packages
	reporter := sarif.NewAggregatingReporter(workDir)

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

	// Run analyzer on each package and collect findings
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

		// Extract findings from result and add to reporter
		if result != nil {
			if rt, ok := result.(*leakhound.ResultType); ok {
				reporter.AddFindings(rt.Findings, pkg.Fset)
			}
		}
	}

	// Build and output single SARIF document
	if err := reporter.Report(os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "failed to encode SARIF: %v\n", err)
		os.Exit(1)
	}
}
