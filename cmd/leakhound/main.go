package main

import (
	"fmt"
	"go/ast"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/nilpoona/leakhound"
	"github.com/nilpoona/leakhound/config"
	"github.com/nilpoona/leakhound/detector"
	"github.com/nilpoona/leakhound/reporter/sarif"
	"golang.org/x/tools/go/analysis/singlechecker"
	"golang.org/x/tools/go/packages"
)

// CLI entry point. The default driver is now the whole-program loader
// (packages.Load with NeedDeps) so cross-package data flow can resolve
// callee bodies in other packages. The legacy per-package driver based on
// singlechecker.Main is retained behind --single-package for compatibility
// with `go vet`-style integrations and for diagnosing differences during
// the SSA migration discussed in the design doc §7.
func main() {
	args := os.Args[1:]

	singlePackage := false
	format := "text"
	configPath := ""
	rest := make([]string, 0, len(args))

	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--single-package" || a == "-single-package":
			singlePackage = true
		case a == "--format=sarif" || a == "-format=sarif":
			format = "sarif"
		case a == "--format=text" || a == "-format=text":
			format = "text"
		case a == "--format" || a == "-format":
			if i+1 < len(args) {
				format = args[i+1]
				i++
			}
		case strings.HasPrefix(a, "--config="):
			configPath = strings.TrimPrefix(a, "--config=")
		case strings.HasPrefix(a, "-config="):
			configPath = strings.TrimPrefix(a, "-config=")
		case a == "--config" || a == "-config":
			if i+1 < len(args) {
				configPath = args[i+1]
				i++
			}
		default:
			rest = append(rest, a)
		}
	}

	if singlePackage {
		// Restore the original argv (minus --single-package) so the standard
		// driver parses --format / --config itself.
		os.Args = append([]string{os.Args[0]}, filterArgs(args, "--single-package", "-single-package")...)
		singlechecker.Main(leakhound.Analyzer)
		return
	}

	if len(rest) == 0 {
		fmt.Fprintln(os.Stderr, "usage: leakhound [--format=text|sarif] [--config=PATH] [--single-package] <package patterns>")
		os.Exit(1)
	}

	if err := runWholeProgram(rest, format, configPath); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

func filterArgs(args []string, drop ...string) []string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		if slices.Contains(drop, a) {
			continue
		}
		out = append(out, a)
	}
	return out
}

func runWholeProgram(patterns []string, format, configPath string) error {
	workDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get working directory: %w", err)
	}

	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		return err
	}

	pkgCfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
			packages.NeedImports | packages.NeedDeps | packages.NeedTypes |
			packages.NeedTypesSizes | packages.NeedSyntax | packages.NeedTypesInfo,
		Tests: false,
		Dir:   workDir,
		Fset:  token.NewFileSet(),
	}

	pkgs, err := packages.Load(pkgCfg, patterns...)
	if err != nil {
		return fmt.Errorf("failed to load packages: %w", err)
	}

	// Surface load errors but continue with whatever loaded successfully —
	// matches staticcheck/gosec behavior for partial successes.
	for _, pkg := range pkgs {
		for _, perr := range pkg.Errors {
			fmt.Fprintf(os.Stderr, "%v\n", perr)
		}
	}

	allPkgs := flattenWithDeps(pkgs)

	world := detector.NewWorldView(pkgCfg.Fset, allPkgs)
	wp := detector.NewWholeProgramCollector(world, &cfg)
	wp.Collect()
	findings := wp.Analyze()

	filter := &detector.SuppressionFilter{}
	filter.Build(collectFiles(allPkgs), pkgCfg.Fset)
	findings = filter.Apply(findings, pkgCfg.Fset, &cfg)

	switch format {
	case "sarif":
		rep := sarif.NewAggregatingReporter(workDir)
		rep.AddFindings(findings, pkgCfg.Fset)
		return rep.Report(os.Stdout)
	default:
		emitText(findings, pkgCfg.Fset, workDir)
		return nil
	}
}

// flattenWithDeps returns the input packages plus all transitively imported
// packages with parsed syntax. Whole-program analysis needs callee bodies in
// every package the user's code touches, not just the top-level patterns.
func flattenWithDeps(roots []*packages.Package) []*packages.Package {
	seen := make(map[string]*packages.Package)
	var visit func(p *packages.Package)
	visit = func(p *packages.Package) {
		if p == nil {
			return
		}
		if _, ok := seen[p.PkgPath]; ok {
			return
		}
		// Only retain packages whose syntax we have. Packages.Load may
		// surface stdlib entries with NeedDeps but without Syntax depending
		// on the Mode bits — we keep just the ones we can analyze.
		if p.TypesInfo == nil || p.Types == nil {
			return
		}
		seen[p.PkgPath] = p
		for _, imp := range p.Imports {
			visit(imp)
		}
	}
	for _, r := range roots {
		visit(r)
	}
	out := make([]*packages.Package, 0, len(seen))
	for _, p := range seen {
		out = append(out, p)
	}
	return out
}

func collectFiles(pkgs []*packages.Package) []*ast.File {
	var out []*ast.File
	for _, p := range pkgs {
		out = append(out, p.Syntax...)
	}
	return out
}

// emitText writes findings to stderr in the per-line format used by the
// per-package singlechecker mode, so existing tooling and the user-visible
// rule-ID suffix stay unchanged.
func emitText(findings []detector.Finding, fset *token.FileSet, workDir string) {
	for _, f := range findings {
		if f.Suppressed {
			continue
		}
		pos := fset.Position(f.Pos)
		path := pos.Filename
		if rel, err := filepath.Rel(workDir, path); err == nil && !strings.HasPrefix(rel, "..") {
			path = "./" + filepath.ToSlash(rel)
		}
		fmt.Fprintf(os.Stderr, "%s:%d:%d: %s [%s]\n", path, pos.Line, pos.Column, f.Message, f.SARIFRuleID())
	}
}
