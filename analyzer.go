package leakhound

import (
	"github.com/nilpoona/leakhound/detector"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
)

const Doc = `leakhound detects whether fields tagged with sensitive are being output in slog.

It reports an error when struct fields tagged with sensitive:"true" are passed to 
logging functions in the log/slog package.

Example:
	type User struct {
		Name     string
		Password string sensitive:"true"
	}

	// NG: Password field is being output to logs
	slog.Info("user", "password", user.Password)
`

var Analyzer = &analysis.Analyzer{
	Name:     "leakhound",
	Doc:      Doc,
	Run:      run,
	Requires: []*analysis.Analyzer{inspect.Analyzer},
}

func run(pass *analysis.Pass) (interface{}, error) {
	// Single-pass collection of all information (sensitive fields, data flow, log calls)
	collector := detector.NewDataFlowCollector(pass)
	collector.Collect()

	// Analyze collected log calls and report sensitive data leaks
	collector.AnalyzeAndReport()

	return nil, nil
}
