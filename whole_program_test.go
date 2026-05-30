package leakhound_test

import (
	"go/token"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/nilpoona/leakhound/config"
	"github.com/nilpoona/leakhound/detector"
	"golang.org/x/tools/go/packages"
)

// TestWholeProgramCrossPackage verifies that the whole-program driver
// reports findings for cross-package data flow (LH0005, LH0006).
//
// The testdata is a self-contained Go module (testdata/crosspkgflow/...)
// rather than the GOPATH-style testdata/src layout used by analysistest,
// because packages.Load with NeedDeps needs a real module graph.
func TestWholeProgramCrossPackage(t *testing.T) {
	dir, err := filepath.Abs("testdata/crosspkgflow")
	if err != nil {
		t.Fatalf("abs path: %v", err)
	}

	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
			packages.NeedImports | packages.NeedDeps | packages.NeedTypes |
			packages.NeedTypesSizes | packages.NeedSyntax | packages.NeedTypesInfo,
		Tests: false,
		Dir:   dir,
		Fset:  token.NewFileSet(),
	}
	roots, err := packages.Load(cfg, "./...")
	if err != nil {
		t.Fatalf("packages.Load: %v", err)
	}
	for _, p := range roots {
		for _, e := range p.Errors {
			t.Logf("pkg %s error: %v", p.PkgPath, e)
		}
	}

	all := flattenForTest(roots)

	world := detector.NewWorldView(cfg.Fset, all)
	wp := detector.NewWholeProgramCollector(world, &config.Config{})
	wp.Collect()
	findings := wp.Analyze()

	// Group findings by file:line for assertion against the //want comments
	// embedded in app.go. We assert the substring after `want "` matches the
	// produced finding message at the same line.
	wantRE := regexp.MustCompile(`//\s*want\s+"([^"]+)"`)
	wantByLine := make(map[string]string)
	for _, p := range all {
		if p.PkgPath != "example.com/crosspkgflow/app" {
			continue
		}
		for _, f := range p.Syntax {
			for _, cg := range f.Comments {
				for _, c := range cg.List {
					m := wantRE.FindStringSubmatch(c.Text)
					if m == nil {
						continue
					}
					pos := cfg.Fset.Position(c.Pos())
					key := key(pos.Filename, pos.Line)
					wantByLine[key] = m[1]
				}
			}
		}
	}

	gotByLine := make(map[string][]string)
	for _, f := range findings {
		pos := cfg.Fset.Position(f.Pos)
		k := key(pos.Filename, pos.Line)
		gotByLine[k] = append(gotByLine[k], f.RuleID+": "+f.Message)
	}

	// Every //want must have at least one matching finding on the same line.
	for k, want := range wantByLine {
		got := gotByLine[k]
		if len(got) == 0 {
			t.Errorf("no finding at %s; wanted match for %q", k, want)
			continue
		}
		matched := false
		// `want` is the analysistest pattern syntax (a regexp); evaluate
		// against each finding message.
		re, err := regexp.Compile(want)
		if err != nil {
			t.Errorf("bad want regexp %q: %v", want, err)
			continue
		}
		for _, g := range got {
			if re.MatchString(g) {
				matched = true
				break
			}
		}
		if !matched {
			t.Errorf("at %s: no finding matched %q; got: %v", k, want, got)
		}
	}

	// SafeCrossPkgCall must not produce any LH0005/LH0006 findings.
	for _, f := range findings {
		pos := cfg.Fset.Position(f.Pos)
		if !strings.Contains(pos.Filename, "app.go") {
			continue
		}
		if f.RuleID != detector.RuleIDCrossPkgSensitiveReturn && f.RuleID != detector.RuleIDCrossPkgSensitiveSink {
			continue
		}
		k := key(pos.Filename, pos.Line)
		if _, expected := wantByLine[k]; !expected {
			t.Errorf("unexpected cross-pkg finding at %s: %s — %s", k, f.RuleID, f.Message)
		}
	}
}

func flattenForTest(roots []*packages.Package) []*packages.Package {
	seen := make(map[string]*packages.Package)
	var visit func(p *packages.Package)
	visit = func(p *packages.Package) {
		if p == nil {
			return
		}
		if _, ok := seen[p.PkgPath]; ok {
			return
		}
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

func key(file string, line int) string {
	return filepath.Base(file) + ":" + itoa(line)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
