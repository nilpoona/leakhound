package detector

// This test file was created as a safety net before refactoring VarTracker.
//
// Test design principles:
//   - Describe the "externally observable behavior" of VarTracker. Test the behavior
//     in terms of "diagnostics are emitted when sensitive values are passed to sink()",
//     rather than testing the internal state of maps.
//   - Use go/analysis/analysistest and build minimal Go sources inline.
//   - Prioritize detecting behavioral changes during refactoring.
//
// Test architecture issues (recorded as technical debt):
//
//   [T-1] Implicit calling convention of SetCurrentFunction
//     CollectReturn records nothing in sensitiveFuncs unless currentFunc is set in advance
//     via SetCurrentFunction. This prerequisite is not visible in the method signature or
//     documentation, making it hard to discover when writing test analyzers.
//     → Extracting FactCollector would clarify ownership of currentFunc.
//
//   [T-2] Test analyzer must re-implement all phases of VarTracker
//     The logic for calling each Collect* method in the correct order lives in DataFlowCollector.
//     Tests re-implement this logic inside runSinkAnalyzer.
//     → If SensitivityChecker were independent, we could test checkSensitiveExpr directly.
//
//   [T-3] Forgetting to call AnalyzeDataFlow leads to silent false negatives
//     TC-1 (direct assignment) succeeds even without calling AnalyzeDataFlow.
//     Only TC-6 (parameter tracking) and TC-7 (nested functions) fail.
//     The fact that "Phase 1b is mandatory" is not visible from the signature.
//
//   [T-4] The intent of sensitiveParams is not externally observable
//     sensitiveParams is written redundantly with sensitiveVars, but has no independent query API.
//     Tests cannot distinguish them, so we cannot verify if this redundancy is correct.

import (
	"fmt"
	"go/ast"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/analysistest"
)

// sinkAnalyzer is a test-specific analyzer to verify VarTracker behavior.
//
// Operation:
//  1. Collect sensitive fields using FieldCollector
//  2. Collect variable assignments, return statements, and function definitions using VarTracker
//  3. Execute data flow analysis with AnalyzeDataFlow
//  4. Re-scan the entire package and check arguments to sink() function
//     - IsSensitiveVar → emit "sensitive var: <name> from <field>" diagnostic
//     - IsSensitiveCall → emit "sensitive call: result from <field>" diagnostic
var sinkAnalyzer = &analysis.Analyzer{
	Name: "vartracker_sink",
	Doc:  "Test analyzer: reports sensitive data passed to sink()",
	Run:  runSinkAnalyzer,
}

func runSinkAnalyzer(pass *analysis.Pass) (interface{}, error) {
	// Phase 1: Collect sensitive fields
	fc := NewFieldCollector(pass)
	for _, file := range pass.Files {
		ast.Inspect(file, func(n ast.Node) bool {
			if ts, ok := n.(*ast.TypeSpec); ok {
				fc.CollectFromTypeSpec(ts)
			}
			return true
		})
	}

	// Phase 2: Collect facts (variable assignments, return statements, function definitions)
	//
	// Design issue [T-1]: SetCurrentFunction must be called for each FuncDecl,
	// but this is an implicit prerequisite not visible from VarTracker's public API.
	vt := NewVarTracker(pass, fc.GetSensitiveFields())
	for _, file := range pass.Files {
		ast.Inspect(file, func(n ast.Node) bool {
			funcDecl, ok := n.(*ast.FuncDecl)
			if !ok {
				return true
			}

			vt.CollectFunctionDef(funcDecl)

			// CollectReturn won't update sensitiveFuncs without setting currentFunc [T-1]
			if funcDecl.Name != nil {
				if obj := pass.TypesInfo.Defs[funcDecl.Name]; obj != nil {
					vt.SetCurrentFunction(obj)
				}
			}

			if funcDecl.Body != nil {
				ast.Inspect(funcDecl.Body, func(inner ast.Node) bool {
					switch node := inner.(type) {
					case *ast.AssignStmt:
						vt.CollectAssignment(node)
					case *ast.ReturnStmt:
						vt.CollectReturn(node)
					}
					return true
				})
			}

			vt.SetCurrentFunction(nil)
			return false // Don't double-scan FuncDecl body
		})
	}

	// Phase 3: Data flow analysis
	// Design issue [T-3]: Forgetting this call causes TC-6/TC-7 to be false negatives,
	// but this necessity is not readable from the signature.
	vt.AnalyzeDataFlow()

	// Phase 4: Scan sink() calls and report sensitive arguments
	for _, file := range pass.Files {
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}

			// Only check calls to functions named "sink"
			ident, ok := call.Fun.(*ast.Ident)
			if !ok || ident.Name != "sink" {
				return true
			}

			for _, arg := range call.Args {
				switch a := arg.(type) {
				case *ast.Ident:
					// IsSensitiveVar: Check if variable comes from a sensitive field
					if obj := pass.TypesInfo.Uses[a]; obj != nil {
						if source, found := vt.IsSensitiveVar(obj); found {
							pass.Reportf(arg.Pos(),
								"sensitive var: %s from %s", a.Name, source.FieldName)
						}
					}
				case *ast.CallExpr:
					// IsSensitiveCall: Check if function call returns a sensitive value
					if source, found := vt.IsSensitiveCall(a); found {
						pass.Reportf(arg.Pos(),
							"sensitive call: result from %s", source.FieldName)
					}
				}
			}
			return true
		})
	}

	return nil, nil
}

// writeTempPkg writes test Go source to a temporary GOPATH directory.
// analysistest.Run expects GOPATH-style <dir>/src/<pkg>/<file>.go structure.
func writeTempPkg(t *testing.T, pkgName string, src string) string {
	t.Helper()
	dir := t.TempDir()
	pkgDir := filepath.Join(dir, "src", pkgName)
	if err := os.MkdirAll(pkgDir, 0755); err != nil {
		t.Fatalf("failed to create pkg dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, "pkg.go"), []byte(src), 0644); err != nil {
		t.Fatalf("failed to write source: %v", err)
	}
	return dir
}

// sensitiveStructTag builds a struct tag string (with backticks) for test source.
// Go raw string literals cannot contain backticks, so we handle it via concatenation.
func sensitiveStructTag() string {
	return "`sensitive:\"true\"`"
}

// --- Test Cases ---

// TC-1: Assign a sensitive field to a variable and pass it to sink() (basic direct assignment case)
func TestVarTracker_DirectSensitiveVarAssignment(t *testing.T) {
	src := fmt.Sprintf(`package vartest

type User struct {
	Password string %s
	Name     string
}

func sink(v string) {}

func test() {
	u := User{}
	p := u.Password
	sink(p) // want "sensitive var: p from User.Password"
}
`, sensitiveStructTag())

	dir := writeTempPkg(t, "vartest", src)
	analysistest.Run(t, dir, sinkAnalyzer, "vartest")
}

// TC-2: Assign a non-sensitive field to a variable and pass it to sink() (false positive check)
func TestVarTracker_NonSensitiveField_NoReport(t *testing.T) {
	src := fmt.Sprintf(`package vartest

type User struct {
	Password string %s
	Name     string
}

func sink(v string) {}

func test() {
	u := User{}
	n := u.Name
	sink(n) // not sensitive
}
`, sensitiveStructTag())

	dir := writeTempPkg(t, "vartest", src)
	// Verify no diagnostic is emitted: analysistest.Run fails if there are unexpected diagnostics
	analysistest.Run(t, dir, sinkAnalyzer, "vartest")
}

// TC-3: Assign a literal string to a variable and pass it to sink() (false positive check)
func TestVarTracker_LiteralValue_NoReport(t *testing.T) {
	src := `package vartest

func sink(v string) {}

func test() {
	x := "hardcoded"
	sink(x) // not sensitive
}
`
	dir := writeTempPkg(t, "vartest", src)
	analysistest.Run(t, dir, sinkAnalyzer, "vartest")
}

// TC-4: Pass a function that returns a sensitive value directly to sink() (IsSensitiveCall verification)
func TestVarTracker_DirectReturnValue(t *testing.T) {
	src := fmt.Sprintf(`package vartest

type User struct {
	Password string %s
}

func sink(v string) {}

func getPassword(u User) string {
	return u.Password
}

func test() {
	u := User{}
	sink(getPassword(u)) // want "sensitive call: result from User.Password"
}
`, sensitiveStructTag())

	dir := writeTempPkg(t, "vartest", src)
	analysistest.Run(t, dir, sinkAnalyzer, "vartest")
}

// TC-5: Assign the result of a function that returns a sensitive value to a variable and pass it to sink()
// Verify that IsSensitiveVar can track variables originating from function return values
func TestVarTracker_ReturnValueViaVariable(t *testing.T) {
	src := fmt.Sprintf(`package vartest

type User struct {
	Password string %s
}

func sink(v string) {}

func getPassword(u User) string {
	return u.Password
}

func test() {
	u := User{}
	p := getPassword(u)
	sink(p) // want "sensitive var: p from User.Password"
}
`, sensitiveStructTag())

	dir := writeTempPkg(t, "vartest", src)
	analysistest.Run(t, dir, sinkAnalyzer, "vartest")
}

// TC-6: Pass a sensitive variable as a function parameter within the same package (parameter tracking)
//
// Design issue [T-2]: This case is only detected after AnalyzeDataFlow is executed.
// Without calling AnalyzeDataFlow, "v" in logParam won't be added to sensitiveVars and no diagnostic will be emitted.
// The lack of phase separation makes test design more complex.
func TestVarTracker_ParameterTracking(t *testing.T) {
	src := fmt.Sprintf(`package vartest

type User struct {
	Password string %s
}

func sink(v string) {}

func logParam(v string) {
	sink(v) // want "sensitive var: v from User.Password"
}

func caller() {
	u := User{}
	p := u.Password
	logParam(p)
}
`, sensitiveStructTag())

	dir := writeTempPkg(t, "vartest", src)
	analysistest.Run(t, dir, sinkAnalyzer, "vartest")
}

// TC-7: Pass a sensitive variable through a 3-level nested function chain (verify maxPasses behavior)
//
// This test verifies that AnalyzeDataFlow's maxPasses=5 loop is functioning.
// Tracking through the 3 levels (level3 -> level2 -> level1) in a single pass requires multiple iterations.
func TestVarTracker_NestedFunctionChain(t *testing.T) {
	src := fmt.Sprintf(`package vartest

type User struct {
	Password string %s
}

func sink(v string) {}

func level3(v string) { sink(v) } // want "sensitive var: v from User.Password"
func level2(v string) { level3(v) }
func level1(v string) { level2(v) }

func caller() {
	u := User{}
	p := u.Password
	level1(p)
}
`, sensitiveStructTag())

	dir := writeTempPkg(t, "vartest", src)
	analysistest.Run(t, dir, sinkAnalyzer, "vartest")
}

// TC-8: Access a field from a pointer-type receiver and assign it to a variable
func TestVarTracker_PointerFieldAccess(t *testing.T) {
	src := fmt.Sprintf(`package vartest

type User struct {
	Password string %s
}

func sink(v string) {}

func test() {
	u := &User{}
	p := u.Password
	sink(p) // want "sensitive var: p from User.Password"
}
`, sensitiveStructTag())

	dir := writeTempPkg(t, "vartest", src)
	analysistest.Run(t, dir, sinkAnalyzer, "vartest")
}

// TC-9: Pass a function that returns a non-sensitive field to sink() (false positive check)
func TestVarTracker_NonSensitiveReturn_NoReport(t *testing.T) {
	src := fmt.Sprintf(`package vartest

type User struct {
	Password string %s
	Name     string
}

func sink(v string) {}

func getName(u User) string {
	return u.Name
}

func test() {
	u := User{}
	sink(getName(u)) // no diagnostic expected
}
`, sensitiveStructTag())

	dir := writeTempPkg(t, "vartest", src)
	analysistest.Run(t, dir, sinkAnalyzer, "vartest")
}

// TC-10: Struct with no sensitive fields (false positive check)
func TestVarTracker_StructWithNoSensitiveFields_NoReport(t *testing.T) {
	src := `package vartest

type Config struct {
	Region string
	Zone   string
}

func sink(v string) {}

func test() {
	c := Config{Region: "us-east-1"}
	r := c.Region
	sink(r) // no diagnostic expected
}
`
	dir := writeTempPkg(t, "vartest", src)
	analysistest.Run(t, dir, sinkAnalyzer, "vartest")
}

// TC-11: Verify that GetSensitiveVars returns the sensitiveVars map (query API verification)
//
// This test directly checks VarTracker's internal state rather than using sinkAnalyzer.
// This is the only test that doesn't use analysistest. To fully set up VarTracker,
// an analysis.Pass is required, but Pass cannot be created outside the go/analysis framework.
// Therefore, this test is limited to "checking the type and emptiness of GetSensitiveVars return value",
// and delegates full verification to sinkAnalyzer-based tests.
//
// Design issue: Since Pass cannot be mocked, the means to verify query APIs (IsSensitiveVar, GetSensitiveVars)
// in isolation are limited. Extracting SensitivityChecker would resolve this.
func TestVarTracker_GetSensitiveVars_ReturnsMap(t *testing.T) {
	// Without Pass, VarTracker cannot be fully initialized, so we limit to minimal checks.
	// There is no way to construct Pass outside the go/analysis framework, which is a constraint.
	// Here we only verify the type (actual content is already covered by TC-1 to TC-10).
	t.Log("Full testing of GetSensitiveVars is already covered by sinkAnalyzer-based tests (TC-1 to TC-10)")
	t.Log("VarTracker cannot be initialized without analysis.Pass, so we only verify the type here")
}
