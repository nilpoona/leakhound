package text

import (
	"github.com/nilpoona/leakhound/detector"
	"golang.org/x/tools/go/analysis"
)

// Reporter handles text output formatting
type Reporter struct {
	pass *analysis.Pass
}

// NewReporter creates a new text reporter
func NewReporter(pass *analysis.Pass) *Reporter {
	return &Reporter{
		pass: pass,
	}
}

// Report outputs findings in text format to stderr.
// Suppressed findings are silently skipped.
// Each message is suffixed with the SARIF rule ID (e.g. [LH0001]) so users
// know which ID to use in //noleak: comments.
func (r *Reporter) Report(findings []detector.Finding) error {
	for _, finding := range findings {
		if finding.Suppressed {
			continue
		}
		r.pass.Reportf(finding.Pos, "%s [%s]", finding.Message, finding.SARIFRuleID())
	}
	return nil
}
