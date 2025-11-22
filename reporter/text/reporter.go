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

// Report outputs findings in text format to stderr
func (r *Reporter) Report(findings []detector.Finding) error {
	for _, finding := range findings {
		r.pass.Reportf(finding.Pos, "%s", finding.Message)
	}
	return nil
}
