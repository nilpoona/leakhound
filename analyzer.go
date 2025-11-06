package leakhound

import (
	"go/ast"

	"github.com/nilpoona/leakhound/detector"
	"github.com/nilpoona/leakhound/fmtchecker"
	"github.com/nilpoona/leakhound/logchecker"
	"github.com/nilpoona/leakhound/slogchecker"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
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
	inspect := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)

	// Step 1: Collect all data flow information in a single pass
	collector := detector.NewDataFlowCollector(pass)
	collector.Collect()

	// Step 2: Inspect logging calls and check for sensitive data
	nodeFilter := []ast.Node{
		(*ast.CallExpr)(nil),
	}

	inspect.Preorder(nodeFilter, func(n ast.Node) {
		call := n.(*ast.CallExpr)

		if !slogchecker.IsSlogCall(call, pass) &&
			!fmtchecker.IsFmtCall(call, pass) &&
			!logchecker.IsLogCall(call, pass) {
			return
		}

		// Inspect arguments for sensitive data
		for _, arg := range call.Args {
			collector.CheckArgForSensitiveData(arg)
		}
	})

	return nil, nil
}
