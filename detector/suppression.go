package detector

import (
	"go/ast"
	"go/token"
	"strings"

	"github.com/nilpoona/leakhound/config"
)

// SuppressionFilter applies suppression rules to findings.
// It supports inline comments (//noleak:LH0001, //noleak:all)
// and config-level rule suppression.
//
// Inline comment placement: a //noleak directive is matched against the finding
// if it appears on the SAME LINE as the finding, or on the IMMEDIATELY PRECEDING
// LINE (line - 1). This covers both trailing comments and standalone comments
// directly above multi-line call expressions. Comments two or more lines above
// are NOT matched.
type SuppressionFilter struct {
	// index maps filename → line → slice of SARIF rule IDs (or "all")
	index map[string]map[int][]string
}

// Build scans AST file comments to build the suppression index.
// Must be called before Apply.
func (sf *SuppressionFilter) Build(files []*ast.File, fset *token.FileSet) {
	sf.index = make(map[string]map[int][]string)
	for _, file := range files {
		for _, cg := range file.Comments {
			for _, c := range cg.List {
				rule, ok := parseNoleak(c.Text)
				if !ok {
					continue
				}
				pos := fset.Position(c.Pos())
				if sf.index[pos.Filename] == nil {
					sf.index[pos.Filename] = make(map[int][]string)
				}
				sf.index[pos.Filename][pos.Line] = append(sf.index[pos.Filename][pos.Line], rule)
			}
		}
	}
}

// Apply marks findings as Suppressed based on inline comments and config rules.
// Returns the same slice with Suppressed fields updated.
func (sf *SuppressionFilter) Apply(findings []Finding, fset *token.FileSet, cfg *config.Config) []Finding {
	configSuppressed := make(map[string]bool, len(cfg.Suppress.Rules))
	for _, r := range cfg.Suppress.Rules {
		configSuppressed[r] = true
	}

	for i := range findings {
		sarifID := findings[i].SARIFRuleID()

		if configSuppressed[sarifID] {
			findings[i].Suppressed = true
			findings[i].SuppressionKind = "external"
			continue
		}

		pos := fset.Position(findings[i].Pos)
	outer:
		for _, line := range []int{pos.Line, pos.Line - 1} {
			for _, r := range sf.index[pos.Filename][line] {
				if r == "all" || r == sarifID {
					findings[i].Suppressed = true
					findings[i].SuppressionKind = "inSource"
					break outer
				}
			}
		}
	}

	return findings
}

// parseNoleak parses a //noleak:RULE_ID comment.
// Returns the rule ID and true if the comment is a valid noleak directive.
// Only //noleak: (no leading space after //) is accepted.
// Any text after the rule ID (separated by whitespace) is ignored,
// allowing //noleak:LH0001 with an explanatory tail.
func parseNoleak(text string) (string, bool) {
	const prefix = "//noleak:"
	if !strings.HasPrefix(text, prefix) {
		return "", false
	}
	rest := text[len(prefix):]
	// Trim at first whitespace — ignore any trailing explanation text
	if idx := strings.IndexAny(rest, " \t"); idx >= 0 {
		rest = rest[:idx]
	}
	if rest == "" {
		return "", false
	}
	return rest, true
}
