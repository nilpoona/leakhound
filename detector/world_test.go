package detector

import (
	"go/ast"
	"go/token"
	"go/types"
	"testing"

	"golang.org/x/tools/go/packages"
)

func TestNewWorldView_PkgByPath(t *testing.T) {
	t.Parallel()
	fset := token.NewFileSet()
	a := &packages.Package{PkgPath: "example.com/a"}
	b := &packages.Package{PkgPath: "example.com/b"}
	w := NewWorldView(fset, []*packages.Package{a, b, nil})

	if w.Fset != fset {
		t.Errorf("Fset not stored")
	}
	if w.pkgByPath["example.com/a"] != a {
		t.Errorf("pkgByPath missing 'a'")
	}
	if w.pkgByPath["example.com/b"] != b {
		t.Errorf("pkgByPath missing 'b'")
	}
	if _, ok := w.pkgByPath[""]; ok {
		// nil entry must not pollute the map
		t.Errorf("pkgByPath unexpectedly contains empty key")
	}
}

func TestNewWorldView_EmptyMaps(t *testing.T) {
	t.Parallel()
	w := NewWorldView(token.NewFileSet(), nil)

	// All accessors must return non-nil, empty maps so callers can freely
	// write to them without preceding nil-checks.
	if w.SensitiveFields() == nil {
		t.Error("SensitiveFields nil")
	}
	if w.SensitiveVars() == nil {
		t.Error("SensitiveVars nil")
	}
	if w.SensitiveFuncs() == nil {
		t.Error("SensitiveFuncs nil")
	}
	if w.SensitiveFuncPos() == nil {
		t.Error("SensitiveFuncPos nil")
	}
	if w.SensitiveParams() == nil {
		t.Error("SensitiveParams nil")
	}
	if w.SinkParams() == nil {
		t.Error("SinkParams nil")
	}
	if w.FuncDefs() == nil {
		t.Error("FuncDefs nil")
	}
}

func TestWorldView_Accessors_ReturnSharedMaps(t *testing.T) {
	t.Parallel()
	w := NewWorldView(token.NewFileSet(), nil)

	// Verify accessor methods return the same underlying map (not a copy),
	// because per-package collectors write through these accessors and the
	// whole-program analyzer must observe their writes.
	w.SensitiveFields()[sensitiveField{typeName: "T", fieldName: "F"}] = true
	if !w.SensitiveFields()[sensitiveField{typeName: "T", fieldName: "F"}] {
		t.Errorf("SensitiveFields write not visible via accessor")
	}

	w.SinkParams()[fakeVar("p")] = true
	if len(w.SinkParams()) != 1 {
		t.Errorf("SinkParams write not visible: %v", w.SinkParams())
	}
}

func TestWorldView_RegisterFunc(t *testing.T) {
	t.Parallel()
	w := NewWorldView(token.NewFileSet(), nil)
	pkg := &packages.Package{PkgPath: "example.com/x"}
	obj := fakeFunc("F")
	decl := &ast.FuncDecl{Name: ast.NewIdent("F")}

	w.RegisterFunc(obj, decl, pkg)

	if got := w.PackageOf(obj); got != pkg {
		t.Errorf("PackageOf = %v, want %v", got, pkg)
	}
	if got := w.FuncDefs()[obj]; got != decl {
		t.Errorf("FuncDefs[obj] = %v, want %v", got, decl)
	}
}

func TestWorldView_RegisterFunc_NilObjectIsNoop(t *testing.T) {
	t.Parallel()
	w := NewWorldView(token.NewFileSet(), nil)
	pkg := &packages.Package{PkgPath: "example.com/x"}
	decl := &ast.FuncDecl{}

	// RegisterFunc must tolerate a nil object — collectors call it via
	// pass.TypesInfo.Defs lookup which can legitimately return nil for
	// declarations affected by build constraints.
	w.RegisterFunc(nil, decl, pkg)

	if len(w.FuncDefs()) != 0 {
		t.Errorf("FuncDefs should remain empty after nil-obj register, got %d", len(w.FuncDefs()))
	}
}

func TestWorldView_PackageOf_UnknownReturnsNil(t *testing.T) {
	t.Parallel()
	w := NewWorldView(token.NewFileSet(), nil)
	if w.PackageOf(fakeFunc("Unknown")) != nil {
		t.Error("PackageOf of unregistered func should be nil")
	}
}

// fakeVar is a tiny helper to mint *types.Var values for identity testing.
func fakeVar(name string) *types.Var {
	return types.NewVar(token.NoPos, nil, name, types.Typ[types.String])
}
