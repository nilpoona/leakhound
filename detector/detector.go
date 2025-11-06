package detector

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"golang.org/x/tools/go/analysis"
)

// sensitiveField holds information about fields with sensitive tags
type sensitiveField struct {
	typeName  string
	fieldName string
}

// CollectSensitiveFields collects fields with sensitive tags
func CollectSensitiveFields(pass *analysis.Pass) map[sensitiveField]bool {
	fields := make(map[sensitiveField]bool)
	sensitiveTypes := make(map[string]bool)

	// First pass: collect directly sensitive fields
	for _, file := range pass.Files {
		ast.Inspect(file, func(n ast.Node) bool {
			typeSpec, ok := n.(*ast.TypeSpec)
			if !ok {
				return true
			}

			structType, ok := typeSpec.Type.(*ast.StructType)
			if !ok {
				return true
			}

			typeName := typeSpec.Name.Name

			// Check tags for each field
			for _, field := range structType.Fields.List {
				if field.Tag == nil {
					continue
				}

				tagValue := strings.Trim(field.Tag.Value, "`")
				if !HasSensitiveTag(tagValue) {
					continue
				}

				// Record fields with sensitive tags
				for _, name := range field.Names {
					fields[sensitiveField{
						typeName:  typeName,
						fieldName: name.Name,
					}] = true
				}

				// Mark this type as containing sensitive fields
				sensitiveTypes[typeName] = true
			}

			return true
		})
	}

	// Second pass: collect structs with embedded sensitive types
	for _, file := range pass.Files {
		ast.Inspect(file, func(n ast.Node) bool {
			typeSpec, ok := n.(*ast.TypeSpec)
			if !ok {
				return true
			}

			structType, ok := typeSpec.Type.(*ast.StructType)
			if !ok {
				return true
			}

			typeName := typeSpec.Name.Name

			// Check for embedded structs with sensitive fields
			for _, field := range structType.Fields.List {
				// Embedded struct has no field name
				if len(field.Names) == 0 {
					// Get the embedded type name
					if ident, ok := field.Type.(*ast.Ident); ok {
						embeddedTypeName := ident.Name
						// If the embedded type contains sensitive fields, mark parent as sensitive
						if sensitiveTypes[embeddedTypeName] {
							sensitiveTypes[typeName] = true
						}
					}
				}
			}

			return true
		})
	}

	return fields
}

// HasSensitiveTag checks if the tag string contains sensitive:"true"
func HasSensitiveTag(tag string) bool {
	// Support both sensitive:"true" and sensitive:\"true\" formats
	return strings.Contains(tag, `sensitive:"true"`) ||
		strings.Contains(tag, `sensitive:\"true\"`)
}

// hasAnySensitiveFields checks if a struct type has any fields with sensitive tags
func hasAnySensitiveFields(typeName string, sensitiveFields map[sensitiveField]bool) bool {
	for sf := range sensitiveFields {
		if sf.typeName == typeName {
			return true
		}
	}
	return false
}

// hasAnySensitiveFieldsFromType checks if a struct type has any sensitive fields using type info
// This also checks for embedded structs with sensitive fields
func hasAnySensitiveFieldsFromType(pass *analysis.Pass, named *types.Named) bool {
	return checkStructForSensitiveFields(pass, named, make(map[string]bool))
}

// CheckArgForSensitiveFields checks if the argument contains sensitive fields
func CheckArgForSensitiveFields(pass *analysis.Pass, arg ast.Expr, sensitiveFields map[sensitiveField]bool) {
	// First check if the argument itself is a struct with sensitive fields
	if tv, ok := pass.TypesInfo.Types[arg]; ok {
		typ := tv.Type
		// Get element type if it's a pointer type
		if ptr, ok := typ.(*types.Pointer); ok {
			typ = ptr.Elem()
		}

		// Check if the entire struct has sensitive fields
		if named, ok := typ.(*types.Named); ok {
			// Add nil check for named type object to handle build constraint issues
			obj := named.Obj()
			if obj == nil {
				return
			}
			typeName := obj.Name()

			// Check local cache first
			if hasAnySensitiveFields(typeName, sensitiveFields) {
				pass.Reportf(arg.Pos(),
					"struct '%s' contains sensitive fields and should not be logged entirely",
					typeName)
				return
			}

			// If not found in local cache, check using type info
			if hasAnySensitiveFieldsFromType(pass, named) {
				pass.Reportf(arg.Pos(),
					"struct '%s' contains sensitive fields and should not be logged entirely",
					typeName)
				return
			}
		}
	}

	// Then check for field access within the argument (including nested function calls)
	ast.Inspect(arg, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.SelectorExpr:
			// Handle field access like config.Secret
			checkFieldAccess(pass, node, sensitiveFields)
		case *ast.CallExpr:
			// Handle function calls like slog.Any("data", config)
			for _, callArg := range node.Args {
				CheckArgForSensitiveFields(pass, callArg, sensitiveFields)
			}
			return false // Don't traverse into call expr again
		}
		return true
	})
}

// checkFieldAccess checks if a selector expression accesses a sensitive field
func checkFieldAccess(pass *analysis.Pass, sel *ast.SelectorExpr, sensitiveFields map[sensitiveField]bool) {
	// Get the type of field access
	tv, ok := pass.TypesInfo.Types[sel.X]
	if !ok {
		return
	}

	// Get element type if it's a pointer type
	typ := tv.Type
	if ptr, ok := typ.(*types.Pointer); ok {
		typ = ptr.Elem()
	}

	// Case for struct type
	named, ok := typ.(*types.Named)
	if !ok {
		return
	}

	// Add nil check for named type object to handle build constraint issues
	obj := named.Obj()
	if obj == nil {
		return
	}

	typeName := obj.Name()
	fieldName := sel.Sel.Name

	// First check local sensitive fields cache
	sf := sensitiveField{
		typeName:  typeName,
		fieldName: fieldName,
	}

	if sensitiveFields[sf] {
		pass.Reportf(sel.Pos(),
			"sensitive field '%s.%s' should not be logged (tagged with sensitive:\"true\")",
			typeName, fieldName)
		return
	}

	// If not found in local cache, check the actual struct definition using type info
	if checkSensitiveFieldFromTypeInfo(pass, named, fieldName) {
		pass.Reportf(sel.Pos(),
			"sensitive field '%s.%s' should not be logged (tagged with sensitive:\"true\")",
			typeName, fieldName)
	}
}

// checkSensitiveFieldFromTypeInfo checks if a field has sensitive tag using type information
// This also checks embedded structs for the field
func checkSensitiveFieldFromTypeInfo(pass *analysis.Pass, named *types.Named, fieldName string) bool {
	// Get the underlying struct type
	underlying, ok := named.Underlying().(*types.Struct)
	if !ok {
		return false
	}

	// Find the field
	for i := 0; i < underlying.NumFields(); i++ {
		field := underlying.Field(i)
		if field.Name() == fieldName {
			// Get the struct tag
			tag := underlying.Tag(i)
			return HasSensitiveTag(tag)
		}

		// Check embedded structs for the field
		if field.Embedded() {
			fieldType := field.Type()

			// Handle pointer to embedded struct
			if ptr, ok := fieldType.(*types.Pointer); ok {
				fieldType = ptr.Elem()
			}

			// Check if the embedded type is a named struct
			if namedType, ok := fieldType.(*types.Named); ok {
				if checkSensitiveFieldFromTypeInfo(pass, namedType, fieldName) {
					return true
				}
			}
		}
	}

	return false
}

// checkStructForSensitiveFields checks if a struct type has any sensitive fields using type info
// This recursively checks embedded structs as well
func checkStructForSensitiveFields(pass *analysis.Pass, named *types.Named, visited map[string]bool) bool {
	// Get the underlying struct type
	underlying, ok := named.Underlying().(*types.Struct)
	if !ok {
		return false
	}

	// Prevent infinite recursion for circular struct references
	typeName := named.Obj().Name()
	if visited[typeName] {
		return false
	}
	visited[typeName] = true

	// Check all fields for sensitive tags
	for i := 0; i < underlying.NumFields(); i++ {
		field := underlying.Field(i)
		tag := underlying.Tag(i)

		// Check if this field has a sensitive tag
		if HasSensitiveTag(tag) {
			return true
		}

		// Check if this is an embedded struct with sensitive fields
		if field.Embedded() {
			fieldType := field.Type()

			// Handle pointer to embedded struct
			if ptr, ok := fieldType.(*types.Pointer); ok {
				fieldType = ptr.Elem()
			}

			// Check if the embedded type is a named struct
			if namedType, ok := fieldType.(*types.Named); ok {
				if checkStructForSensitiveFields(pass, namedType, visited) {
					return true
				}
			}
		}
	}

	return false
}

// SensitiveSource describes where a sensitive value came from
type SensitiveSource struct {
	FieldName string      // Original sensitive field name (e.g., "User.Password")
	Position  token.Pos   // Position where the value was assigned/passed
	FlowPath  []string    // Data flow path for nested tracking
}

// DataFlowCollector collects data flow information in a single AST pass
type DataFlowCollector struct {
	pass *analysis.Pass

	// Collected information (minimal storage)
	sensitiveFields map[sensitiveField]bool        // Sensitive fields from tags
	sensitiveVars   map[*types.Var]SensitiveSource // Variables assigned from sensitive fields
	sensitiveFuncs  map[types.Object]SensitiveSource // Functions that return sensitive values
	sensitiveParams map[*types.Var]SensitiveSource // Function parameters that receive sensitive values

	// Function definitions for parameter tracking
	funcDefs map[types.Object]*ast.FuncDecl

	// Current context during traversal
	currentFunc types.Object

	// Visited tracking to prevent infinite recursion
	visitedFuncs map[types.Object]bool
}

// NewDataFlowCollector creates a new collector
func NewDataFlowCollector(pass *analysis.Pass) *DataFlowCollector {
	return &DataFlowCollector{
		pass:            pass,
		sensitiveFields: make(map[sensitiveField]bool),
		sensitiveVars:   make(map[*types.Var]SensitiveSource),
		sensitiveFuncs:  make(map[types.Object]SensitiveSource),
		sensitiveParams: make(map[*types.Var]SensitiveSource),
		funcDefs:        make(map[types.Object]*ast.FuncDecl),
		visitedFuncs:    make(map[types.Object]bool),
	}
}

// Collect performs single-pass AST traversal to collect all information
func (c *DataFlowCollector) Collect() {
	// First pass: collect all sensitive fields, assignments, and function definitions
	for _, file := range c.pass.Files {
		c.collectFromFile(file)
	}

	// After collection, analyze data flow
	c.analyzeDataFlow()
}

// collectFromFile collects information from a single file
func (c *DataFlowCollector) collectFromFile(file *ast.File) {
	ast.Inspect(file, func(n ast.Node) bool {
		if n == nil {
			return false
		}

		switch node := n.(type) {
		case *ast.TypeSpec:
			c.collectSensitiveFields(node)
		case *ast.FuncDecl:
			c.collectFunctionDef(node)
			c.collectFromFunction(node)
			return false // Don't traverse into function body again
		}

		return true
	})
}

// collectFromFunction collects information from within a function
func (c *DataFlowCollector) collectFromFunction(funcDecl *ast.FuncDecl) {
	// Set current function context
	if funcDecl.Name != nil {
		if obj := c.pass.TypesInfo.Defs[funcDecl.Name]; obj != nil {
			c.currentFunc = obj
		}
	}

	// Traverse function body
	if funcDecl.Body != nil {
		ast.Inspect(funcDecl.Body, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.AssignStmt:
				c.collectAssignment(node)
			case *ast.ReturnStmt:
				c.collectReturn(node)
			}
			return true
		})
	}

	// Reset current function context
	c.currentFunc = nil
}

// collectSensitiveFields collects struct fields with sensitive tags
func (c *DataFlowCollector) collectSensitiveFields(typeSpec *ast.TypeSpec) {
	structType, ok := typeSpec.Type.(*ast.StructType)
	if !ok {
		return
	}

	typeName := typeSpec.Name.Name

	for _, field := range structType.Fields.List {
		if field.Tag == nil {
			continue
		}

		tagValue := strings.Trim(field.Tag.Value, "`")
		if !HasSensitiveTag(tagValue) {
			continue
		}

		for _, name := range field.Names {
			c.sensitiveFields[sensitiveField{
				typeName:  typeName,
				fieldName: name.Name,
			}] = true
		}
	}
}

// collectFunctionDef collects function definitions
func (c *DataFlowCollector) collectFunctionDef(funcDecl *ast.FuncDecl) {
	// Get function object from type info
	if funcDecl.Name == nil {
		return
	}

	obj := c.pass.TypesInfo.Defs[funcDecl.Name]
	if obj == nil {
		return
	}

	c.funcDefs[obj] = funcDecl
}

// collectAssignment checks if an assignment assigns a sensitive field to a variable
func (c *DataFlowCollector) collectAssignment(assign *ast.AssignStmt) {
	// Handle assignments: variable := expr
	for i, lhs := range assign.Lhs {
		if i >= len(assign.Rhs) {
			continue
		}
		rhs := assign.Rhs[i]

		// Get the variable being assigned to
		var varObj *types.Var
		switch l := lhs.(type) {
		case *ast.Ident:
			if obj := c.pass.TypesInfo.Defs[l]; obj != nil {
				if v, ok := obj.(*types.Var); ok {
					varObj = v
				}
			}
		}

		if varObj == nil {
			continue
		}

		// Check if RHS is a sensitive field access
		if source := c.checkSensitiveExpr(rhs); source != nil {
			c.sensitiveVars[varObj] = *source
		}
	}
}

// collectReturn collects return statements
func (c *DataFlowCollector) collectReturn(ret *ast.ReturnStmt) {
	// Only handle single return values for now (per spec)
	if len(ret.Results) != 1 {
		return
	}

	// Check if the returned expression is sensitive
	if source := c.checkSensitiveExpr(ret.Results[0]); source != nil {
		// Mark the current function as returning sensitive data
		if c.currentFunc != nil {
			c.sensitiveFuncs[c.currentFunc] = *source
		}
	}
}

// checkSensitiveExpr checks if an expression is sensitive
func (c *DataFlowCollector) checkSensitiveExpr(expr ast.Expr) *SensitiveSource {
	switch e := expr.(type) {
	case *ast.SelectorExpr:
		// Direct field access: user.Password
		return c.checkSensitiveFieldAccess(e)

	case *ast.Ident:
		// Variable reference: password
		if obj := c.pass.TypesInfo.Uses[e]; obj != nil {
			if v, ok := obj.(*types.Var); ok {
				if source, found := c.sensitiveVars[v]; found {
					return &source
				}
			}
		}

	case *ast.CallExpr:
		// Function call: getPassword(user)
		if funObj := c.getFunctionObject(e.Fun); funObj != nil {
			if source, found := c.sensitiveFuncs[funObj]; found {
				return &source
			}
		}
	}

	return nil
}

// checkSensitiveFieldAccess checks if a selector expression is a sensitive field access
func (c *DataFlowCollector) checkSensitiveFieldAccess(sel *ast.SelectorExpr) *SensitiveSource {
	// Get the type of the base expression
	tv, ok := c.pass.TypesInfo.Types[sel.X]
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

	// Check if this field is sensitive
	sf := sensitiveField{
		typeName:  typeName,
		fieldName: fieldName,
	}

	if c.sensitiveFields[sf] {
		return &SensitiveSource{
			FieldName: fmt.Sprintf("%s.%s", typeName, fieldName),
			Position:  sel.Pos(),
			FlowPath:  []string{fmt.Sprintf("%s.%s", typeName, fieldName)},
		}
	}

	return nil
}

// getFunctionObject gets the function object from a call expression
func (c *DataFlowCollector) getFunctionObject(fun ast.Expr) types.Object {
	switch f := fun.(type) {
	case *ast.Ident:
		if obj := c.pass.TypesInfo.Uses[f]; obj != nil {
			return obj
		}
	case *ast.SelectorExpr:
		if obj := c.pass.TypesInfo.Uses[f.Sel]; obj != nil {
			return obj
		}
	}
	return nil
}

// analyzeDataFlow performs data flow analysis after collection
func (c *DataFlowCollector) analyzeDataFlow() {
	// Track function calls to propagate sensitive parameters
	// Use multiple passes to handle nested function calls
	maxPasses := 5 // Limit iterations to prevent infinite loops
	changed := true

	for pass := 0; pass < maxPasses && changed; pass++ {
		changed = false
		c.visitedFuncs = make(map[types.Object]bool) // Reset visited for each pass

		for funcObj, funcDecl := range c.funcDefs {
			beforeCount := len(c.sensitiveVars)
			c.analyzeFunctionCalls(funcObj, funcDecl)
			if len(c.sensitiveVars) > beforeCount {
				changed = true
			}
		}
	}
}

// analyzeFunctionCalls tracks sensitive variables passed as function parameters
func (c *DataFlowCollector) analyzeFunctionCalls(funcObj types.Object, funcDecl *ast.FuncDecl) {
	// Update current function context
	oldFunc := c.currentFunc
	c.currentFunc = funcObj
	defer func() { c.currentFunc = oldFunc }()

	// Check if already visited to prevent infinite recursion
	if c.visitedFuncs[funcObj] {
		return
	}
	c.visitedFuncs[funcObj] = true

	// Traverse function body to find calls
	if funcDecl.Body == nil {
		return
	}

	ast.Inspect(funcDecl.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		// Get the called function
		calledFunc := c.getFunctionObject(call.Fun)
		if calledFunc == nil {
			return true
		}

		// Only track same-package functions
		if calledFunc.Pkg() == nil || calledFunc.Pkg() != c.pass.Pkg {
			return true
		}

		// Get the function definition
		calledFuncDecl, found := c.funcDefs[calledFunc]
		if !found || calledFuncDecl.Type == nil || calledFuncDecl.Type.Params == nil {
			return true
		}

		// Map arguments to parameters
		params := calledFuncDecl.Type.Params.List
		paramIdx := 0

		for _, arg := range call.Args {
			if paramIdx >= len(params) {
				break
			}

			param := params[paramIdx]

			// Check if this argument is sensitive
			if source := c.checkSensitiveExpr(arg); source != nil {
				// Mark each parameter name as sensitive
				for _, paramName := range param.Names {
					if paramObj := c.pass.TypesInfo.Defs[paramName]; paramObj != nil {
						if v, ok := paramObj.(*types.Var); ok {
							// Create new source with updated flow path
							newSource := SensitiveSource{
								FieldName: source.FieldName,
								Position:  arg.Pos(),
								FlowPath:  append(append([]string{}, source.FlowPath...), fmt.Sprintf("parameter '%s'", paramName.Name)),
							}
							c.sensitiveParams[v] = newSource
							c.sensitiveVars[v] = newSource
						}
					}
				}
			}

			// Move to next parameter
			if len(param.Names) > 0 {
				paramIdx++
			}
		}

		return true
	})
}

// GetSensitiveFields returns the collected sensitive fields
func (c *DataFlowCollector) GetSensitiveFields() map[sensitiveField]bool {
	return c.sensitiveFields
}

// GetSensitiveVars returns the collected sensitive variables
func (c *DataFlowCollector) GetSensitiveVars() map[*types.Var]SensitiveSource {
	return c.sensitiveVars
}

// IsSensitiveVar checks if a variable is sensitive
func (c *DataFlowCollector) IsSensitiveVar(obj types.Object) (SensitiveSource, bool) {
	if v, ok := obj.(*types.Var); ok {
		source, found := c.sensitiveVars[v]
		return source, found
	}
	return SensitiveSource{}, false
}

// IsSensitiveCall checks if a function call returns sensitive data
func (c *DataFlowCollector) IsSensitiveCall(call *ast.CallExpr) (SensitiveSource, bool) {
	funObj := c.getFunctionObject(call.Fun)
	if funObj == nil {
		return SensitiveSource{}, false
	}

	source, found := c.sensitiveFuncs[funObj]
	return source, found
}

// CheckArgForSensitiveData checks if an argument contains sensitive data
// This includes: direct field access, variables, function calls, and entire structs
func (c *DataFlowCollector) CheckArgForSensitiveData(arg ast.Expr) {
	// First check if the argument is a sensitive variable or call
	if ident, ok := arg.(*ast.Ident); ok {
		if obj := c.pass.TypesInfo.Uses[ident]; obj != nil {
			if source, found := c.IsSensitiveVar(obj); found {
				c.pass.Reportf(arg.Pos(),
					"variable %q contains sensitive field %q (tagged with sensitive:\"true\")",
					ident.Name, source.FieldName)
				return
			}
		}
	}

	// Check if it's a function call that returns sensitive data
	if call, ok := arg.(*ast.CallExpr); ok {
		if source, found := c.IsSensitiveCall(call); found {
			c.pass.Reportf(arg.Pos(),
				"function call returns sensitive field %q (tagged with sensitive:\"true\")",
				source.FieldName)
			return
		}
	}

	// Check if the argument itself is a struct with sensitive fields
	if tv, ok := c.pass.TypesInfo.Types[arg]; ok {
		typ := tv.Type
		// Get element type if it's a pointer type
		if ptr, ok := typ.(*types.Pointer); ok {
			typ = ptr.Elem()
		}

		// Check if the entire struct has sensitive fields
		if named, ok := typ.(*types.Named); ok {
			// Add nil check for named type object to handle build constraint issues
			obj := named.Obj()
			if obj == nil {
				return
			}
			typeName := obj.Name()

			// Check local cache first
			if hasAnySensitiveFields(typeName, c.sensitiveFields) {
				c.pass.Reportf(arg.Pos(),
					"struct '%s' contains sensitive fields and should not be logged entirely",
					typeName)
				return
			}

			// If not found in local cache, check using type info
			if hasAnySensitiveFieldsFromType(c.pass, named) {
				c.pass.Reportf(arg.Pos(),
					"struct '%s' contains sensitive fields and should not be logged entirely",
					typeName)
				return
			}
		}
	}

	// Check for field access within the argument (including nested function calls)
	ast.Inspect(arg, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.SelectorExpr:
			// Handle field access like config.Secret
			c.checkFieldAccessWithCollector(node)
		case *ast.CallExpr:
			// Handle function calls like slog.Any("data", config)
			for _, callArg := range node.Args {
				c.CheckArgForSensitiveData(callArg)
			}
			return false // Don't traverse into call expr again
		}
		return true
	})
}

// checkFieldAccessWithCollector checks if a selector expression accesses a sensitive field
func (c *DataFlowCollector) checkFieldAccessWithCollector(sel *ast.SelectorExpr) {
	// Get the type of field access
	tv, ok := c.pass.TypesInfo.Types[sel.X]
	if !ok {
		return
	}

	// Get element type if it's a pointer type
	typ := tv.Type
	if ptr, ok := typ.(*types.Pointer); ok {
		typ = ptr.Elem()
	}

	// Case for struct type
	named, ok := typ.(*types.Named)
	if !ok {
		return
	}

	// Add nil check for named type object to handle build constraint issues
	obj := named.Obj()
	if obj == nil {
		return
	}

	typeName := obj.Name()
	fieldName := sel.Sel.Name

	// First check local sensitive fields cache
	sf := sensitiveField{
		typeName:  typeName,
		fieldName: fieldName,
	}

	if c.sensitiveFields[sf] {
		c.pass.Reportf(sel.Pos(),
			"sensitive field '%s.%s' should not be logged (tagged with sensitive:\"true\")",
			typeName, fieldName)
		return
	}

	// If not found in local cache, check the actual struct definition using type info
	if checkSensitiveFieldFromTypeInfo(c.pass, named, fieldName) {
		c.pass.Reportf(sel.Pos(),
			"sensitive field '%s.%s' should not be logged (tagged with sensitive:\"true\")",
			typeName, fieldName)
	}
}
