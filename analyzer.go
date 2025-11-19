package leakhound

import (
	"reflect"

	"github.com/nilpoona/leakhound/detector"
	"github.com/nilpoona/leakhound/reporter"
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
	Name:       "leakhound",
	Doc:        Doc,
	Run:        run,
	Requires:   []*analysis.Analyzer{inspect.Analyzer},
	ResultType: reflect.TypeOf((*ResultType)(nil)),
}

var outputFormat string

func init() {
	Analyzer.Flags.StringVar(&outputFormat, "format", "text", "Output format: text or sarif")
}

// ResultType holds the findings from analysis
type ResultType struct {
	Findings []detector.Finding
}

func run(pass *analysis.Pass) (interface{}, error) {
	// Phase 1: Collection
	collector := detector.NewDataFlowCollector(pass)
	collector.Collect()

	// Phase 2: Detection (returns findings)
	findings := collector.Analyze()

	// For text format, report immediately
	// For SARIF format, the custom driver in cmd/leakhound/main.go handles output
	if outputFormat != "sarif" {
		config := reporter.Config{
			Format: reporter.Format(outputFormat),
		}

		rep, err := reporter.New(pass, config)
		if err != nil {
			return nil, err
		}

		if err := rep.Report(findings); err != nil {
			return nil, err
		}
	}

	// Always return ResultType since it's declared in Analyzer.ResultType
	return &ResultType{Findings: findings}, nil
}
