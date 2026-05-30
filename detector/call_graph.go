package detector

import (
	"go/ast"
	"go/types"
	"slices"
)

// CallSite identifies a single call expression inside a caller function.
// It is intentionally first-class (rather than reconstructed on demand) so
// that whole-program data-flow can iterate edges as a graph, per design doc
// §5 / §7(c). This shape also maps cleanly to ssa.CallSite when the engine
// is rewritten on SSA later.
type CallSite struct {
	Caller *types.Func
	Call   *ast.CallExpr
}

// CallGraph holds resolved static call edges from each call site.
//
// Only static edges (direct calls to a *types.Func resolvable via type
// information) are populated in this MVP. Interface dispatch (CHA/VTA) is
// out of scope for Phase 1-4 and lives in the design doc's Phase 6.
type CallGraph struct {
	// Edges maps each call site to the set of callee functions resolved
	// statically (typically one entry, but kept as a slice to leave room
	// for CHA/VTA expansion later).
	Edges map[CallSite][]*types.Func

	// CallersOf maps a callee function back to the call sites that target
	// it. Useful for workset back-propagation: when a callee's sink/return
	// status changes, callers that depend on it must be reprocessed.
	CallersOf map[*types.Func][]CallSite
}

// NewCallGraph creates an empty call graph.
func NewCallGraph() *CallGraph {
	return &CallGraph{
		Edges:     make(map[CallSite][]*types.Func),
		CallersOf: make(map[*types.Func][]CallSite),
	}
}

// AddEdge records a static call edge from caller (at the given call expr) to
// callee. Duplicates are ignored.
func (g *CallGraph) AddEdge(caller *types.Func, call *ast.CallExpr, callee *types.Func) {
	if caller == nil || call == nil || callee == nil {
		return
	}
	site := CallSite{Caller: caller, Call: call}
	if slices.Contains(g.Edges[site], callee) {
		return
	}
	g.Edges[site] = append(g.Edges[site], callee)
	g.CallersOf[callee] = append(g.CallersOf[callee], site)
}
