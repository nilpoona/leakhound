package detector

import (
	"fmt"
	"go/ast"
	"go/types"
	"sort"
	"strings"

	"github.com/nilpoona/leakhound/config"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/packages"
)

// WholeProgramCollector orchestrates cross-package analysis on top of
// WorldView. It mirrors DataFlowCollector's role but spans every loaded
// package, so sensitive data can be tracked across import boundaries (see
// docs/design/cross-package-tracking.md, How E).
//
// Pipeline:
//  1. Per-package fact collection (sensitive fields, vars, returns, log calls,
//     function decls) into the shared WorldView state.
//  2. Cross-package data flow + sink propagation until convergence.
//  3. Detection over collected log calls, emitting LH0001-LH0006 findings.
type WholeProgramCollector struct {
	world *WorldView
	cfg   *config.Config

	// Per-package collectors retained so detection can reuse the correct
	// LogDetector/Detector/TypesInfo for each log call.
	pkgCollectors map[*packages.Package]*DataFlowCollector

	// Aggregated list of log calls plus the package that owns each call,
	// so detection can resolve types using the correct TypesInfo.
	logCalls []wholeProgramLogCall

	// Resolved static call graph (caller func obj → call site → callees).
	graph *CallGraph
}

type wholeProgramLogCall struct {
	pkg  *packages.Package
	call *ast.CallExpr
	// caller is the func decl that contains this log call, if any. nil for
	// init-like top-level expressions.
	caller types.Object
}

// NewWholeProgramCollector creates a collector over the given WorldView.
func NewWholeProgramCollector(world *WorldView, cfg *config.Config) *WholeProgramCollector {
	if cfg == nil {
		cfg = &config.Config{}
	}
	return &WholeProgramCollector{
		world:         world,
		cfg:           cfg,
		pkgCollectors: make(map[*packages.Package]*DataFlowCollector),
		graph:         NewCallGraph(),
	}
}

// CallGraph returns the resolved call graph (mostly useful for tests).
func (wp *WholeProgramCollector) CallGraph() *CallGraph { return wp.graph }

// Collect runs Phases 1-2: per-package fact collection followed by
// cross-package data flow propagation.
func (wp *WholeProgramCollector) Collect() {
	// Phase 1: collect facts per package into shared world state.
	for _, pkg := range wp.world.Packages {
		if pkg == nil || pkg.Types == nil || pkg.TypesInfo == nil {
			continue
		}
		pass := buildPassForPackage(pkg)
		c := NewDataFlowCollectorForWorld(pass, wp.cfg, wp.world, pkg)
		c.CollectFacts()
		wp.pkgCollectors[pkg] = c
		for _, call := range c.LogCalls() {
			wp.logCalls = append(wp.logCalls, wholeProgramLogCall{
				pkg:    pkg,
				call:   call,
				caller: enclosingFuncForCall(pkg, call),
			})
		}
	}

	// Phase 2: cross-package data flow + sink propagation.
	wp.analyzeCrossPackage()
}

// Analyze runs Phase 3: detection over collected log calls and a separate
// scan for cross-package sink call sites (LH0006). Findings are returned
// sorted by source position (filename, line, column, then rule ID) so output
// is stable across runs regardless of the map-iteration order in which
// packages and function decls are visited.
func (wp *WholeProgramCollector) Analyze() []Finding {
	var findings []Finding
	for _, lc := range wp.logCalls {
		c := wp.pkgCollectors[lc.pkg]
		if c == nil {
			continue
		}
		for _, arg := range lc.call.Args {
			findings = append(findings, wp.checkArg(c, lc, arg)...)
		}
	}
	findings = append(findings, wp.detectCrossPkgSinks()...)
	wp.sortFindings(findings)
	return findings
}

// sortFindings orders findings by resolved source position, with the rule ID
// as a final tiebreaker. The raw token.Pos cannot be compared directly because
// offsets depend on the order files were added to the FileSet — and that order
// follows map iteration over packages, which is non-deterministic. Resolving to
// (filename, line, column) makes the ordering reproducible.
func (wp *WholeProgramCollector) sortFindings(findings []Finding) {
	fset := wp.world.Fset
	if fset == nil {
		return
	}
	sort.SliceStable(findings, func(i, j int) bool {
		pi := fset.Position(findings[i].Pos)
		pj := fset.Position(findings[j].Pos)
		if pi.Filename != pj.Filename {
			return pi.Filename < pj.Filename
		}
		if pi.Line != pj.Line {
			return pi.Line < pj.Line
		}
		if pi.Column != pj.Column {
			return pi.Column < pj.Column
		}
		return findings[i].RuleID < findings[j].RuleID
	})
}

// detectCrossPkgSinks walks every known function body once and reports
// LH0006 for any call site where a sensitive value is passed to a cross-
// package function whose parameter at that position is a known sink.
func (wp *WholeProgramCollector) detectCrossPkgSinks() []Finding {
	var findings []Finding
	for callerObj, callerDecl := range wp.world.funcDefs {
		if callerDecl == nil || callerDecl.Body == nil {
			continue
		}
		callerPkg := wp.world.PackageOf(callerObj)
		if callerPkg == nil {
			continue
		}
		ast.Inspect(callerDecl.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			findings = append(findings, wp.detectSinkAtCallSite(callerPkg, callerObj, call)...)
			return true
		})
	}
	return findings
}

// checkArg dispatches detection for a single argument of a log call. It
// reuses the per-package Detector for LH0001-LH0004 findings and adds the
// cross-package upgrades (LH0005, LH0006).
func (wp *WholeProgramCollector) checkArg(c *DataFlowCollector, lc wholeProgramLogCall, arg ast.Expr) []Finding {
	findings := c.Detector().CheckArgForSensitiveData(arg)
	for i := range findings {
		// Promote sensitive-call findings to cross-package variant when the
		// callee belongs to a different package than the caller.
		if findings[i].RuleID != RuleIDSensitiveCall {
			continue
		}
		call, ok := arg.(*ast.CallExpr)
		if !ok {
			continue
		}
		calleePkg := wp.calleePackagePath(lc.pkg, call)
		if calleePkg == "" || calleePkg == lc.pkg.PkgPath {
			continue
		}
		src, _ := c.VarTracker().IsSensitiveCall(call)
		findings[i].RuleID = RuleIDCrossPkgSensitiveReturn
		findings[i].Message = fmt.Sprintf(
			"cross-package function call returns sensitive field %q (callee in %q)",
			src.FieldName, calleePkg)
	}
	return findings
}

// analyzeCrossPackage runs the convergence-based data flow + sink propagation
// over the world's funcDefs, satisfying design doc §7(d).
//
// It is driven by the static CallGraph rather than a fixed-point loop that
// re-walks every function on every round: a function is (re)processed only when
// a fact it depends on changes. The two dependency edges are
//   - forward: making callee G's parameter sensitive may let G propagate it
//     further, so G is re-enqueued;
//   - backward: making this function's own parameter a sink may let its callers
//     mark their parameters as sinks, so CallersOf(this) are re-enqueued.
//
// Because both sinkParams and sensitiveParams only ever grow (monotone), and
// every re-enqueue corresponds to a concrete state change, the worklist is
// guaranteed to terminate at the same fixpoint the old all-pairs loop reached.
func (wp *WholeProgramCollector) analyzeCrossPackage() {
	// Seed direct sinks: params used inside their owning function's body
	// directly as arguments to a logging call.
	wp.seedDirectSinks()

	// Build the static call graph; CallersOf drives sink back-propagation.
	wp.buildCallGraph()

	queue := make([]types.Object, 0, len(wp.world.funcDefs))
	inQueue := make(map[types.Object]bool, len(wp.world.funcDefs))
	enqueue := func(obj types.Object) {
		if obj == nil || inQueue[obj] {
			return
		}
		// Only schedule functions whose body we actually hold; cross-package
		// callees without a loaded decl (e.g. stdlib) cannot propagate.
		if _, ok := wp.world.funcDefs[obj]; !ok {
			return
		}
		inQueue[obj] = true
		queue = append(queue, obj)
	}

	// Prime the worklist with every known function (one initial visit each,
	// equivalent to the first full pass of the old loop).
	for funcObj := range wp.world.funcDefs {
		enqueue(funcObj)
	}

	// Safety bound: total meaningful work is bounded by the number of state
	// changes (≤ 2×params) times graph fan-in, but cap defensively so a logic
	// bug can never spin forever. Never expected to be hit in practice.
	maxSteps := len(wp.world.funcDefs)*64 + 1<<16
	for steps := 0; len(queue) > 0 && steps < maxSteps; steps++ {
		obj := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		inQueue[obj] = false
		for _, dep := range wp.propagateThroughFunc(obj, wp.world.funcDefs[obj]) {
			enqueue(dep)
		}
	}
}

// propagateThroughFunc walks one function's body once, propagating sensitivity
// forward (arg→param) and sink-ness backward (callee.param→caller.param). It
// returns the set of function objects whose facts changed as a result and
// therefore need (re)processing:
//   - each callee whose parameter newly became sensitive, and
//   - when this function's own parameter newly became a sink, every caller of
//     this function (via CallGraph.CallersOf).
func (wp *WholeProgramCollector) propagateThroughFunc(callerObj types.Object, callerDecl *ast.FuncDecl) []types.Object {
	if callerDecl == nil || callerDecl.Body == nil {
		return nil
	}
	callerPkg := wp.world.PackageOf(callerObj)
	if callerPkg == nil || callerPkg.TypesInfo == nil {
		return nil
	}
	callerInfo := callerPkg.TypesInfo

	// Resolve caller's own parameters so we can detect "this arg refers to
	// our own param P" for sink back-propagation.
	callerParams := paramSet(callerDecl, callerInfo)

	var toEnqueue []types.Object
	callerParamBecameSink := false
	markCallerSink := func(p *types.Var) {
		if !wp.world.sinkParams[p] {
			wp.world.sinkParams[p] = true
			callerParamBecameSink = true
		}
	}

	ast.Inspect(callerDecl.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		// Sink back-propagation: if this call is a log call and any arg
		// references a caller param, that param is now a sink.
		if c := wp.pkgCollectors[callerPkg]; c != nil && c.LogDetector().IsLogCallWithInfo(call, callerInfo) {
			for _, arg := range call.Args {
				if p := identifiedParam(arg, callerInfo, callerParams); p != nil {
					markCallerSink(p)
				}
			}
			return true
		}

		// Otherwise this is a regular call. Resolve callee and its decl.
		calleeObj := resolveCallee(call.Fun, callerInfo)
		if calleeObj == nil {
			return true
		}
		calleeDecl, hasDecl := wp.world.funcDefs[calleeObj]
		var calleeParams []*types.Var
		if hasDecl {
			if calleePkg := wp.world.PackageOf(calleeObj); calleePkg != nil {
				calleeParams = paramObjects(calleeDecl, calleePkg.TypesInfo)
			}
		}

		for argIdx, arg := range call.Args {
			// Forward propagation: arg(sensitive) → callee.param(sensitive)
			if argIdx < len(calleeParams) && calleeParams[argIdx] != nil {
				paramVar := calleeParams[argIdx]
				if _, already := wp.world.sensitiveParams[paramVar]; !already {
					if src := wp.evalSensitive(arg, callerInfo); src != nil {
						newSource := SensitiveSource{
							FieldName: src.FieldName,
							Position:  arg.Pos(),
							FlowPath:  append(append([]string{}, src.FlowPath...), fmt.Sprintf("parameter '%s'", paramVar.Name())),
						}
						wp.world.sensitiveParams[paramVar] = newSource
						wp.world.sensitiveVars[paramVar] = newSource
						// The callee now carries sensitivity inward; let it
						// propagate from its own body.
						toEnqueue = append(toEnqueue, calleeObj)
					}
				}
			}

			// Sink back-propagation: arg refers to caller's param AND callee's
			// param at this index is a sink → caller's param is a sink.
			if argIdx < len(calleeParams) && calleeParams[argIdx] != nil && wp.world.sinkParams[calleeParams[argIdx]] {
				if p := identifiedParam(arg, callerInfo, callerParams); p != nil {
					markCallerSink(p)
				}
			}
		}
		return true
	})

	// If this function's own parameter became a sink, its callers may now mark
	// their arguments' parameters as sinks too — re-enqueue them via the graph.
	if callerParamBecameSink {
		if callerFunc, ok := callerObj.(*types.Func); ok {
			for _, site := range wp.graph.CallersOf[callerFunc] {
				toEnqueue = append(toEnqueue, site.Caller)
			}
		}
	}
	return toEnqueue
}

// seedDirectSinks finds params that are directly fed into a logging call
// inside their owning function body. The convergent workset propagates
// transitively after this seeding step.
func (wp *WholeProgramCollector) seedDirectSinks() {
	for funcObj, funcDecl := range wp.world.funcDefs {
		if funcDecl.Body == nil {
			continue
		}
		pkg := wp.world.PackageOf(funcObj)
		if pkg == nil || pkg.TypesInfo == nil {
			continue
		}
		c := wp.pkgCollectors[pkg]
		if c == nil {
			continue
		}
		params := paramSet(funcDecl, pkg.TypesInfo)
		if len(params) == 0 {
			continue
		}
		ast.Inspect(funcDecl.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if !c.LogDetector().IsLogCallWithInfo(call, pkg.TypesInfo) {
				return true
			}
			for _, arg := range call.Args {
				if p := identifiedParam(arg, pkg.TypesInfo, params); p != nil {
					wp.world.sinkParams[p] = true
				}
			}
			return true
		})
	}
}

// buildCallGraph populates the static call graph from all known function
// bodies. CallersOf drives sink back-propagation in analyzeCrossPackage; a
// future SSA migration will replace this with callgraph.CHA / VTA output
// (see design doc §7(c)).
func (wp *WholeProgramCollector) buildCallGraph() {
	for funcObj, funcDecl := range wp.world.funcDefs {
		callerFunc, ok := funcObj.(*types.Func)
		if !ok || funcDecl.Body == nil {
			continue
		}
		pkg := wp.world.PackageOf(funcObj)
		if pkg == nil || pkg.TypesInfo == nil {
			continue
		}
		ast.Inspect(funcDecl.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if calleeObj := resolveCallee(call.Fun, pkg.TypesInfo); calleeObj != nil {
				if calleeFunc, ok := calleeObj.(*types.Func); ok {
					wp.graph.AddEdge(callerFunc, call, calleeFunc)
				}
			}
			return true
		})
	}
}

// detectSinkAtCallSite emits an LH0006 finding when a call passes a sensitive
// value to a callee whose parameter at that position is a known sink, AND
// the call site is in a package different from the callee's package.
func (wp *WholeProgramCollector) detectSinkAtCallSite(callerPkg *packages.Package, _ types.Object, call *ast.CallExpr) []Finding {
	if callerPkg == nil || callerPkg.TypesInfo == nil {
		return nil
	}
	calleeObj := resolveCallee(call.Fun, callerPkg.TypesInfo)
	if calleeObj == nil {
		return nil
	}
	calleeDecl, ok := wp.world.funcDefs[calleeObj]
	if !ok {
		return nil
	}
	calleePkg := wp.world.PackageOf(calleeObj)
	if calleePkg == nil || calleePkg.PkgPath == callerPkg.PkgPath {
		return nil
	}
	calleeParams := paramObjects(calleeDecl, calleePkg.TypesInfo)

	var findings []Finding
	for argIdx, arg := range call.Args {
		if argIdx >= len(calleeParams) || calleeParams[argIdx] == nil {
			continue
		}
		if !wp.world.sinkParams[calleeParams[argIdx]] {
			continue
		}
		src := wp.evalSensitive(arg, callerPkg.TypesInfo)
		if src == nil {
			continue
		}
		findings = append(findings, Finding{
			Pos: arg.Pos(),
			Message: fmt.Sprintf(
				"sensitive field %q is passed to cross-package function %q whose parameter %q is logged downstream",
				src.FieldName, calleeObj.Name(), calleeParams[argIdx].Name()),
			RuleID: RuleIDCrossPkgSensitiveSink,
		})
	}
	return findings
}

// evalSensitive checks whether an expression resolves to sensitive data given
// a TypesInfo. It is the cross-package analogue of SensitivityChecker.checkSensitiveExpr.
func (wp *WholeProgramCollector) evalSensitive(expr ast.Expr, info *types.Info) *SensitiveSource {
	if info == nil {
		return nil
	}
	switch e := expr.(type) {
	case *ast.SelectorExpr:
		return wp.sensitiveFieldAccessWithInfo(e, info)
	case *ast.Ident:
		if obj := info.Uses[e]; obj != nil {
			if v, ok := obj.(*types.Var); ok {
				if src, ok := wp.world.sensitiveVars[v]; ok {
					return &src
				}
			}
		}
	case *ast.CallExpr:
		if obj := resolveCallee(e.Fun, info); obj != nil {
			if src, ok := wp.world.sensitiveFuncs[obj]; ok {
				return &src
			}
		}
	}
	return nil
}

// sensitiveFieldAccessWithInfo mirrors SensitivityChecker.checkSensitiveFieldAccess
// but takes TypesInfo so it can be called for AST nodes in any package.
func (wp *WholeProgramCollector) sensitiveFieldAccessWithInfo(sel *ast.SelectorExpr, info *types.Info) *SensitiveSource {
	tv, ok := info.Types[sel.X]
	if !ok {
		return nil
	}
	typ := tv.Type
	if ptr, ok := typ.(*types.Pointer); ok {
		typ = ptr.Elem()
	}
	named, ok := typ.(*types.Named)
	if !ok {
		return nil
	}
	obj := named.Obj()
	if obj == nil {
		return nil
	}
	typeName := obj.Name()
	fieldName := sel.Sel.Name
	if wp.world.sensitiveFields[sensitiveField{typeName: typeName, fieldName: fieldName}] {
		return &SensitiveSource{
			FieldName: fmt.Sprintf("%s.%s", typeName, fieldName),
			Position:  sel.Pos(),
			FlowPath:  []string{fmt.Sprintf("%s.%s", typeName, fieldName)},
		}
	}
	// Fall back to struct-tag lookup so cross-package types without a cached
	// entry are still recognised.
	if checkSensitiveFieldFromTypeInfo(nil, named, fieldName) {
		return &SensitiveSource{
			FieldName: fmt.Sprintf("%s.%s", typeName, fieldName),
			Position:  sel.Pos(),
			FlowPath:  []string{fmt.Sprintf("%s.%s", typeName, fieldName)},
		}
	}
	return nil
}

// calleePackagePath resolves the import path of the callee at a given call
// site, using the caller package's TypesInfo. Returns "" if the callee can't
// be resolved (e.g. dynamic dispatch).
func (wp *WholeProgramCollector) calleePackagePath(callerPkg *packages.Package, call *ast.CallExpr) string {
	if callerPkg == nil || callerPkg.TypesInfo == nil {
		return ""
	}
	obj := resolveCallee(call.Fun, callerPkg.TypesInfo)
	if obj == nil || obj.Pkg() == nil {
		return ""
	}
	return obj.Pkg().Path()
}

// --- Helpers (file-private) ---

// buildPassForPackage synthesises a minimal analysis.Pass for a loaded
// package. The existing per-package collectors are built around the pass
// abstraction, so reusing them keeps the implementation small.
func buildPassForPackage(pkg *packages.Package) *analysis.Pass {
	return &analysis.Pass{
		Fset:      pkg.Fset,
		Files:     pkg.Syntax,
		Pkg:       pkg.Types,
		TypesInfo: pkg.TypesInfo,
		Report:    func(analysis.Diagnostic) {},
		ResultOf:  map[*analysis.Analyzer]any{},
	}
}

// enclosingFuncForCall locates the function object whose body contains the
// given call expression. Used to attribute cross-package sink findings to
// the correct caller.
func enclosingFuncForCall(pkg *packages.Package, target *ast.CallExpr) types.Object {
	if pkg == nil || pkg.TypesInfo == nil {
		return nil
	}
	for _, file := range pkg.Syntax {
		var found types.Object
		ast.Inspect(file, func(n ast.Node) bool {
			fn, ok := n.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				return true
			}
			contains := false
			ast.Inspect(fn.Body, func(m ast.Node) bool {
				if m == target {
					contains = true
					return false
				}
				return !contains
			})
			if contains && fn.Name != nil {
				if obj := pkg.TypesInfo.Defs[fn.Name]; obj != nil {
					found = obj
				}
				return false
			}
			return true
		})
		if found != nil {
			return found
		}
	}
	return nil
}

// paramObjects returns the flat list of *types.Var corresponding to each
// positional parameter of the given func decl, resolved via the supplied
// TypesInfo. Entries are nil where resolution fails (rare; usually only for
// build-constraint-affected code).
func paramObjects(decl *ast.FuncDecl, info *types.Info) []*types.Var {
	if decl == nil || decl.Type == nil || decl.Type.Params == nil || info == nil {
		return nil
	}
	var params []*types.Var
	for _, field := range decl.Type.Params.List {
		for _, name := range field.Names {
			if obj, ok := info.Defs[name].(*types.Var); ok {
				params = append(params, obj)
			} else {
				params = append(params, nil)
			}
		}
	}
	return params
}

// paramSet returns the set of parameter vars for fast membership testing in
// "does this ident reference one of my params" checks.
func paramSet(decl *ast.FuncDecl, info *types.Info) map[*types.Var]bool {
	objs := paramObjects(decl, info)
	if len(objs) == 0 {
		return nil
	}
	set := make(map[*types.Var]bool, len(objs))
	for _, o := range objs {
		if o != nil {
			set[o] = true
		}
	}
	return set
}

// identifiedParam returns the *types.Var of a caller parameter when the
// argument expression is a direct identifier reference to one. Returns nil
// otherwise (e.g. arg is a literal, a method call, or a field access).
func identifiedParam(arg ast.Expr, info *types.Info, params map[*types.Var]bool) *types.Var {
	id, ok := arg.(*ast.Ident)
	if !ok {
		return nil
	}
	obj, ok := info.Uses[id].(*types.Var)
	if !ok {
		return nil
	}
	if !params[obj] {
		return nil
	}
	return obj
}

// IsStdlibPackagePath reports whether pkgPath belongs to the Go standard
// library. The heuristic: a path is stdlib when its first segment contains no
// dot (e.g. "fmt", "log/slog", "internal/abi"), whereas module paths always
// carry a dotted domain in the first segment ("example.com/x", "github.com/y").
//
// Whole-program analysis excludes stdlib *dependencies* from the WorldView:
// their bodies are never sinks we must propagate through — slog/log/fmt calls
// are recognised directly from type information at the call site — so including
// them only forces the cross-package worklist to re-walk large swaths of stdlib
// on every convergence iteration. Root packages the user explicitly targets are
// kept regardless.
func IsStdlibPackagePath(pkgPath string) bool {
	if pkgPath == "" {
		return false
	}
	first, _, _ := strings.Cut(pkgPath, "/")
	return !strings.Contains(first, ".")
}

// resolveCallee returns the *types.Object representing the function being
// called by the given Fun expression, using the provided TypesInfo. Returns
// nil for non-resolvable calls (dynamic dispatch, type conversions, etc.).
func resolveCallee(fun ast.Expr, info *types.Info) types.Object {
	if info == nil {
		return nil
	}
	switch f := fun.(type) {
	case *ast.Ident:
		return info.Uses[f]
	case *ast.SelectorExpr:
		return info.Uses[f.Sel]
	}
	return nil
}
