package leakhound

import (
	"golang.org/x/tools/go/analysis"
)

// AnalyzerPlugin is the plugin interface for golangci-lint
type AnalyzerPlugin struct{}

// GetAnalyzers returns analyzers (golangci-lint v1.55.0 and later)
func (*AnalyzerPlugin) GetAnalyzers() []*analysis.Analyzer {
	return []*analysis.Analyzer{
		Analyzer,
	}
}

// New creates a golangci-lint plugin
func New(conf any) ([]*analysis.Analyzer, error) {
	return []*analysis.Analyzer{Analyzer}, nil
}
