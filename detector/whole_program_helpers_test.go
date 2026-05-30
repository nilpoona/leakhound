package detector

import (
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"testing"

	"golang.org/x/tools/go/packages"
)

// typeCheckSource parses and type-checks a small Go source string. It is the
// shared fixture for whole_program.go helper tests, which all need a real
// *types.Info populated by go/types so name → object lookups behave the way
// the analyzer does in production.
func typeCheckSource(t *testing.T, src string) (*token.FileSet, *ast.File, *types.Info) {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "test.go", src, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	info := &types.Info{
		Types: make(map[ast.Expr]types.TypeAndValue),
		Defs:  make(map[*ast.Ident]types.Object),
		Uses:  make(map[*ast.Ident]types.Object),
	}
	conf := types.Config{Importer: importer.Default()}
	if _, err := conf.Check("test", fset, []*ast.File{file}, info); err != nil {
		t.Fatalf("type check: %v", err)
	}
	return fset, file, info
}

// findFuncDecl returns the first top-level *ast.FuncDecl with the given name.
func findFuncDecl(t *testing.T, file *ast.File, name string) *ast.FuncDecl {
	t.Helper()
	for _, d := range file.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && fn.Name.Name == name {
			return fn
		}
	}
	t.Fatalf("function %q not found", name)
	return nil
}

func TestParamObjects_Variants(t *testing.T) {
	t.Parallel()
	const src = `package test
func NoParams() {}
func Single(a string) {}
func Grouped(a, b string, c int) {}
`
	_, file, info := typeCheckSource(t, src)

	tests := []struct {
		name      string
		fn        string
		wantNames []string
	}{
		{"no params", "NoParams", nil},
		{"single", "Single", []string{"a"}},
		// Grouped form (a, b string, c int) flattens to three positional
		// parameters in the analyzer's view.
		{"grouped", "Grouped", []string{"a", "b", "c"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fn := findFuncDecl(t, file, tc.fn)
			got := paramObjects(fn, info)
			if len(got) != len(tc.wantNames) {
				t.Fatalf("len = %d, want %d (%v)", len(got), len(tc.wantNames), got)
			}
			for i, want := range tc.wantNames {
				if got[i] == nil {
					t.Errorf("param[%d] nil, want %q", i, want)
					continue
				}
				if got[i].Name() != want {
					t.Errorf("param[%d] name = %q, want %q", i, got[i].Name(), want)
				}
			}
		})
	}
}

func TestParamObjects_NilGuards(t *testing.T) {
	t.Parallel()
	if got := paramObjects(nil, nil); got != nil {
		t.Errorf("paramObjects(nil, nil) = %v, want nil", got)
	}
	if got := paramObjects(&ast.FuncDecl{}, nil); got != nil {
		t.Errorf("paramObjects(empty decl, nil) = %v, want nil", got)
	}
}

func TestParamSet_BuildsMembershipMap(t *testing.T) {
	t.Parallel()
	const src = `package test
func F(a, b string) {}
`
	_, file, info := typeCheckSource(t, src)
	fn := findFuncDecl(t, file, "F")

	set := paramSet(fn, info)
	if len(set) != 2 {
		t.Fatalf("set size = %d, want 2", len(set))
	}
	objs := paramObjects(fn, info)
	for _, o := range objs {
		if !set[o] {
			t.Errorf("param %q not in set", o.Name())
		}
	}
}

func TestParamSet_EmptyFuncReturnsNil(t *testing.T) {
	t.Parallel()
	const src = `package test
func F() {}
`
	_, file, info := typeCheckSource(t, src)
	fn := findFuncDecl(t, file, "F")
	if got := paramSet(fn, info); got != nil {
		t.Errorf("paramSet for empty params = %v, want nil", got)
	}
}

func TestIdentifiedParam(t *testing.T) {
	t.Parallel()
	const src = `package test
func F(a string) {
	_ = a
	_ = "literal"
}
`
	_, file, info := typeCheckSource(t, src)
	fn := findFuncDecl(t, file, "F")
	params := paramSet(fn, info)

	var (
		identArg ast.Expr
		litArg   ast.Expr
	)
	// Walk the body and pick out the two _ = x assignment RHSs.
	for _, stmt := range fn.Body.List {
		if assign, ok := stmt.(*ast.AssignStmt); ok {
			switch v := assign.Rhs[0].(type) {
			case *ast.Ident:
				if v.Name == "a" {
					identArg = v
				}
			case *ast.BasicLit:
				litArg = v
			}
		}
	}
	if identArg == nil || litArg == nil {
		t.Fatalf("could not extract args from body")
	}

	// 'a' refers to caller's param → returns non-nil.
	if got := identifiedParam(identArg, info, params); got == nil {
		t.Errorf("identifiedParam(a) = nil, want the param var")
	} else if got.Name() != "a" {
		t.Errorf("identifiedParam(a).Name = %q, want %q", got.Name(), "a")
	}

	// Literal is not an ident → nil.
	if got := identifiedParam(litArg, info, params); got != nil {
		t.Errorf("identifiedParam(literal) = %v, want nil", got)
	}

	// An ident that resolves to something outside the params set → nil.
	// Build a fresh ident referring to nothing in params.
	otherIdent := ast.NewIdent("zz")
	if got := identifiedParam(otherIdent, info, params); got != nil {
		t.Errorf("identifiedParam(unrelated) = %v, want nil", got)
	}
}

func TestResolveCallee(t *testing.T) {
	t.Parallel()
	const src = `package test
func Helper() {}
type T struct{}
func (T) M() {}
func F() {
	Helper()
	var t T
	t.M()
}
`
	_, file, info := typeCheckSource(t, src)
	fn := findFuncDecl(t, file, "F")

	var calls []*ast.CallExpr
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if c, ok := n.(*ast.CallExpr); ok {
			calls = append(calls, c)
		}
		return true
	})
	if len(calls) != 2 {
		t.Fatalf("expected 2 calls in F body, got %d", len(calls))
	}

	// First call is Helper() — *ast.Ident fun, resolves via Uses.
	if got := resolveCallee(calls[0].Fun, info); got == nil || got.Name() != "Helper" {
		t.Errorf("resolveCallee(Helper) = %v", got)
	}

	// Second call is t.M() — *ast.SelectorExpr fun, resolves via Uses[Sel].
	if got := resolveCallee(calls[1].Fun, info); got == nil || got.Name() != "M" {
		t.Errorf("resolveCallee(t.M) = %v", got)
	}

	// Nil typesInfo → nil.
	if got := resolveCallee(calls[0].Fun, nil); got != nil {
		t.Errorf("resolveCallee with nil info = %v, want nil", got)
	}

	// Unsupported expression shape (e.g. an *ast.ParenExpr wrapping the ident)
	// → nil. Helper only handles Ident / SelectorExpr.
	wrapped := &ast.ParenExpr{X: calls[0].Fun}
	if got := resolveCallee(wrapped, info); got != nil {
		t.Errorf("resolveCallee(paren) = %v, want nil", got)
	}
}

func TestEnclosingFuncForCall(t *testing.T) {
	t.Parallel()
	const src = `package test
func A() { println("a") }
func B() { println("b") }
`
	_, file, info := typeCheckSource(t, src)

	// Pull the println call inside A's body.
	a := findFuncDecl(t, file, "A")
	var targetCall *ast.CallExpr
	ast.Inspect(a.Body, func(n ast.Node) bool {
		if c, ok := n.(*ast.CallExpr); ok {
			targetCall = c
			return false
		}
		return true
	})
	if targetCall == nil {
		t.Fatal("could not find call inside A")
	}

	pkg := &packages.Package{
		Syntax:    []*ast.File{file},
		TypesInfo: info,
	}

	enclosing := enclosingFuncForCall(pkg, targetCall)
	if enclosing == nil {
		t.Fatalf("enclosingFuncForCall returned nil")
	}
	if enclosing.Name() != "A" {
		t.Errorf("enclosing func = %q, want %q", enclosing.Name(), "A")
	}
}

func TestEnclosingFuncForCall_NotFound(t *testing.T) {
	t.Parallel()
	const src = `package test
func A() {}
`
	_, file, info := typeCheckSource(t, src)
	pkg := &packages.Package{Syntax: []*ast.File{file}, TypesInfo: info}

	// A synthetic call that doesn't exist anywhere in the file must yield
	// nil rather than panicking.
	stray := &ast.CallExpr{Fun: ast.NewIdent("x")}
	if got := enclosingFuncForCall(pkg, stray); got != nil {
		t.Errorf("enclosingFuncForCall(stray) = %v, want nil", got)
	}
}

func TestEnclosingFuncForCall_NilPkgOrInfo(t *testing.T) {
	t.Parallel()
	stray := &ast.CallExpr{Fun: ast.NewIdent("x")}
	if got := enclosingFuncForCall(nil, stray); got != nil {
		t.Errorf("enclosingFuncForCall(nil pkg) = %v, want nil", got)
	}
	if got := enclosingFuncForCall(&packages.Package{}, stray); got != nil {
		t.Errorf("enclosingFuncForCall(no TypesInfo) = %v, want nil", got)
	}
}
