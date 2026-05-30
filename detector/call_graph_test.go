package detector

import (
	"go/ast"
	"go/token"
	"go/types"
	"testing"
)

// fakeFunc returns a fresh *types.Func suitable for identity testing in
// graph maps. Avoids constructing a full *types.Package; nil package is fine
// because CallGraph only uses object identity, not metadata.
func fakeFunc(name string) *types.Func {
	sig := types.NewSignatureType(nil, nil, nil, nil, nil, false)
	return types.NewFunc(token.NoPos, nil, name, sig)
}

// fakeCall returns a syntactically valid but minimal *ast.CallExpr. The
// identity of the node is what CallGraph tracks.
func fakeCall() *ast.CallExpr {
	return &ast.CallExpr{Fun: &ast.Ident{Name: "x"}}
}

func TestCallGraph_AddEdge_Basic(t *testing.T) {
	t.Parallel()
	g := NewCallGraph()
	caller := fakeFunc("Caller")
	callee := fakeFunc("Callee")
	call := fakeCall()

	g.AddEdge(caller, call, callee)

	site := CallSite{Caller: caller, Call: call}
	got := g.Edges[site]
	if len(got) != 1 || got[0] != callee {
		t.Fatalf("Edges[site] = %v, want [%v]", got, callee)
	}
	callers := g.CallersOf[callee]
	if len(callers) != 1 || callers[0] != site {
		t.Fatalf("CallersOf[callee] = %v, want [%v]", callers, site)
	}
}

func TestCallGraph_AddEdge_Dedup(t *testing.T) {
	t.Parallel()
	g := NewCallGraph()
	caller := fakeFunc("F")
	callee := fakeFunc("G")
	call := fakeCall()

	// Adding the same edge twice must not duplicate it in either map.
	g.AddEdge(caller, call, callee)
	g.AddEdge(caller, call, callee)

	site := CallSite{Caller: caller, Call: call}
	if got := g.Edges[site]; len(got) != 1 {
		t.Errorf("Edges[site] has %d entries after dedup, want 1: %v", len(got), got)
	}
	if got := g.CallersOf[callee]; len(got) != 1 {
		t.Errorf("CallersOf[callee] has %d entries after dedup, want 1: %v", len(got), got)
	}
}

func TestCallGraph_AddEdge_MultipleCalleesPerSite(t *testing.T) {
	t.Parallel()
	// A single call site can resolve to multiple callees once CHA/VTA edges
	// are added (future Phase 6). The data structure already supports this
	// shape — verify the slice grows and dedup is per (site, callee).
	g := NewCallGraph()
	caller := fakeFunc("F")
	calleeA := fakeFunc("A")
	calleeB := fakeFunc("B")
	call := fakeCall()
	site := CallSite{Caller: caller, Call: call}

	g.AddEdge(caller, call, calleeA)
	g.AddEdge(caller, call, calleeB)
	g.AddEdge(caller, call, calleeA) // duplicate of first

	got := g.Edges[site]
	if len(got) != 2 {
		t.Fatalf("Edges[site] = %v, want 2 entries", got)
	}
	// Order is insertion order; assert the set, not the slice.
	seen := map[*types.Func]bool{}
	for _, c := range got {
		seen[c] = true
	}
	if !seen[calleeA] || !seen[calleeB] {
		t.Errorf("missing callee in Edges: %v", got)
	}
}

func TestCallGraph_AddEdge_NilSafety(t *testing.T) {
	t.Parallel()
	g := NewCallGraph()
	caller := fakeFunc("F")
	callee := fakeFunc("G")
	call := fakeCall()

	// Any nil component must be silently ignored — the workset code calls
	// AddEdge unconditionally and relies on this guard.
	g.AddEdge(nil, call, callee)
	g.AddEdge(caller, nil, callee)
	g.AddEdge(caller, call, nil)

	if len(g.Edges) != 0 {
		t.Errorf("Edges should be empty after nil-only inserts, got %v", g.Edges)
	}
	if len(g.CallersOf) != 0 {
		t.Errorf("CallersOf should be empty after nil-only inserts, got %v", g.CallersOf)
	}
}

func TestCallGraph_CallersOf_AccumulatesAcrossSites(t *testing.T) {
	t.Parallel()
	g := NewCallGraph()
	callerA := fakeFunc("A")
	callerB := fakeFunc("B")
	callee := fakeFunc("Target")
	callA := fakeCall()
	callB := fakeCall()

	g.AddEdge(callerA, callA, callee)
	g.AddEdge(callerB, callB, callee)

	got := g.CallersOf[callee]
	if len(got) != 2 {
		t.Fatalf("CallersOf[callee] = %v, want 2 entries", got)
	}
	seenCallers := map[*types.Func]bool{}
	for _, s := range got {
		seenCallers[s.Caller] = true
	}
	if !seenCallers[callerA] || !seenCallers[callerB] {
		t.Errorf("expected both callers in CallersOf, got %v", got)
	}
}
