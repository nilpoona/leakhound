package ssa

import (
	"go/token"
	"go/types"
	"strings"

	"golang.org/x/tools/go/ssa"
)

// Analyze performs SSA-based data flow analysis to track sensitive values.
// This is the main entry point for SSA analysis.
func (sa *SSAAnalyzer) Analyze() {
	// Phase 1: Collect sensitive fields from struct definitions
	sa.collectSensitiveFields()

	// Phase 2: Iterative data flow analysis
	// Repeat analysis until no new sensitive values are discovered
	const maxIterations = 5
	for iteration := 0; iteration < maxIterations; iteration++ {
		prevCount := len(sa.sensitiveValues)

		// Analyze all functions in the program
		for _, pkg := range sa.prog.AllPackages() {
			for _, member := range pkg.Members {
				if fn, ok := member.(*ssa.Function); ok {
					sa.analyzeFunction(fn)
				}
			}
		}

		// Check if we discovered new sensitive values
		newCount := len(sa.sensitiveValues)
		if newCount == prevCount {
			// Converged - no new sensitive values discovered
			break
		}
	}

	// Phase 3: Propagate sensitivity through function calls
	// SSA provides explicit call graph, making this more precise than AST
	sa.propagateThroughCalls()
}

// collectSensitiveFields scans all types in the program for sensitive:"true" tags.
// This reuses the same logic as the AST-based FieldCollector.
func (sa *SSAAnalyzer) collectSensitiveFields() {
	for _, pkg := range sa.prog.AllPackages() {
		scope := pkg.Pkg.Scope()
		for _, name := range scope.Names() {
			obj := scope.Lookup(name)
			if typeName, ok := obj.(*types.TypeName); ok {
				if named, ok := typeName.Type().(*types.Named); ok {
					if structType, ok := named.Underlying().(*types.Struct); ok {
						sa.scanStructForSensitiveFields(named.Obj().Name(), structType)
					}
				}
			}
		}
	}
}

// scanStructForSensitiveFields checks each field in a struct for sensitive:"true" tag.
func (sa *SSAAnalyzer) scanStructForSensitiveFields(typeName string, structType *types.Struct) {
	for i := 0; i < structType.NumFields(); i++ {
		field := structType.Field(i)
		tag := structType.Tag(i)
		if hasSensitiveTag(tag) {
			key := sensitiveField{
				typeName:  typeName,
				fieldName: field.Name(),
			}
			sa.sensitiveFields[key] = true
		}
	}
}

// hasSensitiveTag checks if a struct tag contains sensitive:"true".
// This is identical to detector.HasSensitiveTag logic.
func hasSensitiveTag(tag string) bool {
	// Support both sensitive:"true" and sensitive:\"true\" formats
	return strings.Contains(tag, `sensitive:"true"`) ||
		strings.Contains(tag, `sensitive:\"true\"`)
}

// analyzeFunction performs data flow analysis on a single SSA function.
// This is where SSA's advantages become clear: each instruction explicitly
// shows value flow, making analysis more straightforward than AST traversal.
func (sa *SSAAnalyzer) analyzeFunction(fn *ssa.Function) {
	if fn.Blocks == nil {
		// External function with no body
		return
	}

	// Analyze each basic block
	for _, block := range fn.Blocks {
		for _, instr := range block.Instrs {
			sa.analyzeInstruction(instr)
		}
	}
}

// analyzeInstruction analyzes a single SSA instruction for sensitive data flow.
func (sa *SSAAnalyzer) analyzeInstruction(instr ssa.Instruction) {
	switch instr := instr.(type) {
	case *ssa.FieldAddr:
		// Field access: &struct.field
		sa.analyzeFieldAddr(instr)
	case *ssa.Field:
		// Field extraction: struct.field (by value)
		sa.analyzeField(instr)
	case *ssa.UnOp:
		// Unary operation (dereference, address-of, etc.)
		sa.analyzeUnOp(instr)
	case *ssa.MakeInterface:
		// Interface conversion
		sa.analyzeMakeInterface(instr)
	case *ssa.Alloc:
		// Memory allocation (local variables, arrays)
		sa.analyzeAlloc(instr)
	case *ssa.Store:
		// Store to memory: *addr = val
		sa.analyzeStore(instr)
	case *ssa.IndexAddr:
		// Array/slice indexing: &arr[i]
		sa.analyzeIndexAddr(instr)
	case *ssa.Slice:
		// Slice operation: arr[:]
		sa.analyzeSlice(instr)
	case *ssa.Call:
		// Function call
		sa.analyzeCall(instr)
	case *ssa.Return:
		// Return statement
		sa.analyzeReturn(instr)
	case *ssa.Phi:
		// Phi node (control flow merge)
		sa.analyzePhi(instr)
	}
}

// analyzeFieldAddr handles field address operations (&struct.field).
// If the field is marked sensitive, the resulting pointer is marked sensitive.
func (sa *SSAAnalyzer) analyzeFieldAddr(instr *ssa.FieldAddr) {
	// Get the struct type
	ptrType, ok := instr.X.Type().(*types.Pointer)
	if !ok {
		return
	}
	structType, ok := ptrType.Elem().Underlying().(*types.Struct)
	if !ok {
		return
	}

	// Check if this field is sensitive
	field := structType.Field(instr.Field)
	if sa.isFieldSensitive(instr.X.Type(), field.Name()) {
		source := &SensitiveSource{
			FieldName: field.Name(),
			TypeName:  getTypeName(instr.X.Type()),
			Pos:       instr.Pos(),
			FlowPath:  []string{"field_addr"},
		}
		sa.MarkSensitive(instr, source)
	}
}

// analyzeField handles field extraction by value (struct.field).
func (sa *SSAAnalyzer) analyzeField(instr *ssa.Field) {
	structType, ok := instr.X.Type().Underlying().(*types.Struct)
	if !ok {
		return
	}

	field := structType.Field(instr.Field)
	if sa.isFieldSensitive(instr.X.Type(), field.Name()) {
		source := &SensitiveSource{
			FieldName: field.Name(),
			TypeName:  getTypeName(instr.X.Type()),
			Pos:       instr.Pos(),
			FlowPath:  []string{"field"},
		}
		sa.MarkSensitive(instr, source)
	}
}

// analyzeUnOp handles unary operations like dereference (*ptr) and address-of (&val).
// For dereference operations, propagate sensitivity from the pointer to the value.
func (sa *SSAAnalyzer) analyzeUnOp(instr *ssa.UnOp) {
	if instr.Op == token.MUL {
		// Dereference: *ptr
		// If the pointer is sensitive, the dereferenced value is also sensitive
		if source := sa.GetSource(instr.X); source != nil {
			sa.MarkSensitive(instr, source)
		}
	}
	// token.AND (&val) doesn't need special handling - if val is sensitive, &val should be too
	// but that's handled by the instruction that produces val
}

// analyzeMakeInterface handles interface conversions.
// If the underlying value is sensitive, the interface is also sensitive.
func (sa *SSAAnalyzer) analyzeMakeInterface(instr *ssa.MakeInterface) {
	if source := sa.GetSource(instr.X); source != nil {
		// Wrapped value is sensitive, so the interface is also sensitive
		sa.MarkSensitive(instr, source)
	}
}

// analyzeAlloc handles memory allocation.
func (sa *SSAAnalyzer) analyzeAlloc(instr *ssa.Alloc) {
	// Alloc creates a pointer to newly allocated memory
	// No inherent sensitivity
}

// analyzeIndexAddr handles array/slice indexing (&arr[i]).
// Propagates sensitivity from the array to the element address.
func (sa *SSAAnalyzer) analyzeIndexAddr(instr *ssa.IndexAddr) {
	// If the array/slice is sensitive, the indexed address is also sensitive
	if source := sa.GetSource(instr.X); source != nil {
		sa.MarkSensitive(instr, source)
	}
}

// analyzeSlice handles slice operations (arr[:], arr[i:j]).
// If the underlying array contains sensitive data, the slice is also sensitive.
func (sa *SSAAnalyzer) analyzeSlice(instr *ssa.Slice) {
	// Check if the source array/slice is sensitive
	if source := sa.GetSource(instr.X); source != nil {
		sa.MarkSensitive(instr, source)
	}
}

// analyzeStore handles store instructions (*addr = val).
// If the stored value is sensitive, mark both the address and the underlying allocation.
func (sa *SSAAnalyzer) analyzeStore(instr *ssa.Store) {
	if source := sa.GetSource(instr.Val); source != nil {
		// The stored value is sensitive
		// Mark the address as sensitive
		sa.MarkSensitive(instr.Addr, source)

		// Also try to mark the underlying allocation
		// If Addr is from IndexAddr, mark the array
		if indexAddr, ok := instr.Addr.(*ssa.IndexAddr); ok {
			sa.MarkSensitive(indexAddr.X, source)
		}
	}
}

// analyzeCall handles function calls.
// This checks if the call is to a logging function and if any arguments are sensitive.
// For non-logging calls, it propagates sensitivity from arguments to parameters.
func (sa *SSAAnalyzer) analyzeCall(instr *ssa.Call) {
	// Check if this is a logging function call
	if sa.isLogCall(instr) {
		// This is a logging call - check all arguments for sensitive data
		for _, arg := range instr.Call.Args {
			if source := sa.GetSource(arg); source != nil {
				// Found sensitive data being logged!
				message := "sensitive field \"" + source.TypeName + "." + source.FieldName +
					"\" is logged and should not be logged"
				sa.addFinding(instr.Pos(), message, "sensitive-field", source)
			}
		}
		return
	}

	// Not a logging call - propagate sensitivity from arguments to parameters
	callee := instr.Call.StaticCallee()
	if callee == nil {
		// Dynamic call (interface method, function pointer, etc.)
		// TODO: Handle dynamic calls in a later phase
		return
	}

	// Only propagate for same-package functions (we have their SSA bodies)
	if callee.Pkg == nil || callee.Pkg != sa.prog.Package(callee.Pkg.Pkg) {
		// External package or builtin - skip for now
		return
	}

	// Propagate sensitivity from arguments to parameters
	for i, arg := range instr.Call.Args {
		if source := sa.GetSource(arg); source != nil {
			// This argument is sensitive
			// Mark the corresponding parameter as sensitive
			if i < len(callee.Params) {
				param := callee.Params[i]
				sa.MarkSensitive(param, source)
			}
		}
	}
}

// isLogCall is now defined in types.go for reuse in debugging methods

// analyzeReturn handles return statements.
// If a returned value is sensitive, mark the function as returning sensitive data.
func (sa *SSAAnalyzer) analyzeReturn(instr *ssa.Return) {
	fn := instr.Parent()
	for _, result := range instr.Results {
		if sa.IsSensitive(result) {
			sa.sensitiveFuncs[fn] = true
			return
		}
	}
}

// analyzePhi handles phi nodes (control flow merge points).
// If any incoming edge is sensitive, the phi result is sensitive.
// This is where flow-sensitivity naturally emerges in SSA.
func (sa *SSAAnalyzer) analyzePhi(instr *ssa.Phi) {
	for _, edge := range instr.Edges {
		if source := sa.GetSource(edge); source != nil {
			// At least one incoming edge is sensitive
			// Phi result is sensitive
			sa.MarkSensitive(instr, source)
			return
		}
	}
}

// propagateThroughCalls propagates sensitivity through function calls.
// This will be implemented in a later phase.
func (sa *SSAAnalyzer) propagateThroughCalls() {
	// TODO: Implement in next phase
	// Use SSA's call graph for precise propagation
}

// isFieldSensitive checks if a field is marked as sensitive.
func (sa *SSAAnalyzer) isFieldSensitive(typ types.Type, fieldName string) bool {
	typeName := getTypeName(typ)
	key := sensitiveField{
		typeName:  typeName,
		fieldName: fieldName,
	}
	return sa.sensitiveFields[key]
}

// getTypeName extracts the type name from a types.Type.
func getTypeName(typ types.Type) string {
	// Handle pointer types
	if ptr, ok := typ.(*types.Pointer); ok {
		typ = ptr.Elem()
	}

	// Get named type
	if named, ok := typ.(*types.Named); ok {
		return named.Obj().Name()
	}

	return ""
}
