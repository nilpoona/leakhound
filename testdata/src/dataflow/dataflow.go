package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
)

type User struct {
	Name     string
	Password string `sensitive:"true"`
}

type Config struct {
	APIKey string `sensitive:"true"`
	Region string
}

// Test Cases for Variable Assignments (TC-001 to TC-008)

func testBasicAssignmentSlog() {
	// TC-001: Basic assignment with slog
	user := User{Name: "alice", Password: "secret123"}
	password := user.Password
	slog.Info("msg", "pass", password) // want "variable \"password\" contains sensitive field \"User.Password\""
}

func testAssignmentLog() {
	// TC-002: Assignment with log package
	user := User{Name: "bob", Password: "secret456"}
	p := user.Password
	log.Println("password:", p) // want "variable \"p\" contains sensitive field \"User.Password\""
}

func testAssignmentFmt() {
	// TC-003: Assignment with fmt
	config := Config{APIKey: "key123", Region: "us-east-1"}
	secret := config.APIKey
	fmt.Printf("secret: %s", secret) // want "variable \"secret\" contains sensitive field \"Config.APIKey\""
}

func testPointerDereferencing() {
	// TC-004: Pointer dereferencing
	user := &User{Name: "charlie", Password: "secret789"}
	password := user.Password
	slog.Info("msg", "pass", password) // want "variable \"password\" contains sensitive field \"User.Password\""
}

func testNestedScope() {
	// TC-006: Variable in nested scope
	user := User{Name: "david", Password: "secretABC"}
	if true {
		password := user.Password
		slog.Info("msg", "pass", password) // want "variable \"password\" contains sensitive field \"User.Password\""
	}
}

func testSlogLoggerMethod() {
	// TC-007: *slog.Logger method
	user := User{Name: "eve", Password: "secretDEF"}
	password := user.Password
	logger := slog.Default()
	logger.Info("msg", "pass", password) // want "variable \"password\" contains sensitive field \"User.Password\""
}

func testLogLoggerMethod() {
	// TC-008: *log.Logger method
	user := User{Name: "frank", Password: "secretGHI"}
	p := user.Password
	customLogger := log.Default()
	customLogger.Println("password:", p) // want "variable \"p\" contains sensitive field \"User.Password\""
}

// Test Cases for Function Parameters (TC-009 to TC-014)

func logValue(val string) {
	slog.Info("msg", "val", val) // want "variable .val. contains sensitive field .User.Password."
}

func testFunctionCallSamePackage() {
	// TC-009: Function call within same package
	user := User{Name: "grace", Password: "secretJKL"}
	password := user.Password
	logValue(password)
}

func inner(data string) {
	log.Println(data) // want "variable .data. contains sensitive field .User.Password."
}

func outer(val string) {
	inner(val)
}

func testNestedFunctionCalls() {
	// TC-010: Nested function calls
	user := User{Name: "henry", Password: "secretMNO"}
	password := user.Password
	outer(password)
}

type Logger struct{}

func (l *Logger) Log(msg string) {
	slog.Info("log", "msg", msg) // want "variable .msg. contains sensitive field .User.Password."
}

func testMethodCall() {
	// TC-011: Method call
	user := User{Name: "iris", Password: "secretPQR"}
	password := user.Password
	logger := &Logger{}
	logger.Log(password)
}

func logWithContext(ctx context.Context, msg string) {
	slog.InfoContext(ctx, "msg", "data", msg) // want "variable .msg. contains sensitive field .Config.APIKey."
}

func testFunctionMultipleParameters() {
	// TC-012: Function with multiple parameters
	config := Config{APIKey: "keyXYZ", Region: "eu-west-1"}
	password := config.APIKey
	logWithContext(context.Background(), password)
}

func logValueDirect(val string) {
	slog.Info("msg", val) // want "variable .val. contains sensitive field .User.Password."
}

func testDirectFieldAccessPassedToFunction() {
	// TC-013: Direct field access passed to function - direct pass not yet tracked
	user := User{Name: "jack", Password: "secretSTU"}
	password := user.Password
	logValueDirect(password)
}

func level3(v string) {
	log.Println(v) // want "variable .v. contains sensitive field .User.Password."
}

func level2(v string) {
	level3(v)
}

func level1(v string) {
	level2(v)
}

func testFunctionChain3Levels() {
	// TC-014: Function chain (3 levels)
	user := User{Name: "kate", Password: "secretVWX"}
	password := user.Password
	level1(password)
}

// Test Cases for Return Values (TC-015 to TC-020)

func getPassword(user User) string {
	return user.Password
}

func testBasicReturnValue() {
	// TC-015: Basic single return value pattern
	user := User{Name: "leo", Password: "secretYZ1"}
	password := getPassword(user)
	slog.Info("msg", password) // want "variable \"password\" contains sensitive field \"User.Password\""
}

func getSecret(config Config) string {
	return config.APIKey
}

func testDirectUseReturnValue() {
	// TC-016: Direct use of return value
	config := Config{APIKey: "keyABC", Region: "ap-south-1"}
	slog.Info("msg", getSecret(config)) // want "function call returns sensitive field \"Config.APIKey\""
}

func extractPassword(user User) string {
	return user.Password
}

func getPasswordNested(user User) string {
	return extractPassword(user)
}

func testNestedFunctionReturnValue() {
	// TC-017: Nested function return value
	user := User{Name: "mary", Password: "secretDEF2"}
	password := getPasswordNested(user)
	slog.Info("msg", password) // want "variable \"password\" contains sensitive field \"User.Password\""
}

type UserWithMethod struct {
	password string `sensitive:"true"`
}

func (u UserWithMethod) GetPassword() string {
	return u.password
}

func testMethodReturnValue() {
	// TC-018: Method return value
	user := UserWithMethod{password: "secretGHI3"}
	password := user.GetPassword()
	slog.Info("msg", password) // want "variable \"password\" contains sensitive field \"UserWithMethod.password\""
}

func getToken(config Config) string {
	return config.APIKey
}

func testReturnValueUsedViaVariable() {
	// TC-019: Return value used via variable
	config := Config{APIKey: "tokenJKL", Region: "us-west-2"}
	token := getToken(config)
	log.Println(token) // want "variable \"token\" contains sensitive field \"Config.APIKey\""
}

func processPassword(user User) string {
	return user.Password
}

func logPassword(user User) {
	pwd := processPassword(user)
	slog.Info("msg", pwd) // want "variable \"pwd\" contains sensitive field \"User.Password\""
}

func testCombinationParameterAndReturn() {
	// TC-020: Combination of function parameter and return value
	user := User{Name: "nancy", Password: "secretMNO4"}
	logPassword(user)
}

// Test Cases for Multi-value Return Values (TC-021 to TC-026)

func getPasswordAndErr(user User) (string, error) {
	return user.Password, nil
}

func testMultiValueReturnBasic() {
	// TC-021: Multi-value return, sensitive at position 0
	user := User{Name: "alice2", Password: "secret"}
	password, err := getPasswordAndErr(user)
	_ = err
	slog.Info("msg", password) // want "variable \"password\" contains sensitive field \"User.Password\""
}

func testMultiValueReturnErrNotFlagged() {
	// TC-022: Position 1 (error) must NOT be flagged
	user := User{Name: "bob2", Password: "secret"}
	_, err := getPasswordAndErr(user)
	slog.Info("msg", "err", fmt.Sprintf("%v", err)) // Should NOT be detected
}

func getAPIKeyAndRegion(config Config) (string, string) {
	return config.APIKey, config.Region
}

func testMultiValueReturnBothPositions() {
	// TC-023: Position 0 sensitive, position 1 not sensitive
	config := Config{APIKey: "key123", Region: "us-east-1"}
	key, region := getAPIKeyAndRegion(config)
	slog.Info("msg", key)    // want "variable \"key\" contains sensitive field \"Config.APIKey\""
	slog.Info("msg", region) // Should NOT be detected
}

func testMultiValueReturnTwoHop() {
	// TC-024: Two-hop chain: v, err := f() → w := v → log(w)
	user := User{Name: "charlie2", Password: "secret"}
	password, err := getPasswordAndErr(user)
	_ = err
	w := password
	slog.Info("msg", w) // want "variable \"w\" contains sensitive field \"User.Password\""
}

func logMultiValueParam(val string) {
	slog.Info("msg", val) // want "variable .val. contains sensitive field .User.Password."
}

func testMultiValueReturnPassToFunction() {
	// TC-025: Multi-value return value passed to function
	user := User{Name: "dave2", Password: "secret"}
	password, err := getPasswordAndErr(user)
	_ = err
	logMultiValueParam(password)
}

func testMultiValueReturnLogPackage() {
	// TC-026: Multi-value return with log package
	user := User{Name: "eve2", Password: "secret"}
	password, err := getPasswordAndErr(user)
	_ = err
	log.Println(password) // want "variable \"password\" contains sensitive field \"User.Password\""
}

// Test Cases for 3+ Return Values (TC-027 to TC-032)

func getNamePasswordErr(user User) (string, string, error) {
	return user.Name, user.Password, nil
}

func testThreeReturnSensitiveAtPosition1() {
	// TC-027: 3 returns, sensitive at position 1 (middle)
	user := User{Name: "frank2", Password: "secret"}
	name, password, err := getNamePasswordErr(user)
	_ = err
	slog.Info("msg", name)     // Should NOT be detected (position 0, Name is not sensitive)
	slog.Info("msg", password) // want "variable \"password\" contains sensitive field \"User.Password\""
}

func getPasswordNameErr(user User) (string, string, error) {
	return user.Password, user.Name, nil
}

func testThreeReturnSensitiveAtPosition0() {
	// TC-028: 3 returns, sensitive at position 0
	user := User{Name: "grace2", Password: "secret"}
	password, name, err := getPasswordNameErr(user)
	_ = err
	slog.Info("msg", password) // want "variable \"password\" contains sensitive field \"User.Password\""
	slog.Info("msg", name)     // Should NOT be detected
}

func getErrNamePassword(user User) (error, string, string) {
	return nil, user.Name, user.Password
}

func testThreeReturnSensitiveAtPosition2() {
	// TC-029: 3 returns, sensitive at last position
	user := User{Name: "henry2", Password: "secret"}
	err, name, password := getErrNamePassword(user)
	_ = err
	slog.Info("msg", name)     // Should NOT be detected
	slog.Info("msg", password) // want "variable \"password\" contains sensitive field \"User.Password\""
}

func getAPIKeyRegionErr(config Config) (string, string, error) {
	return config.APIKey, config.Region, nil
}

func testThreeReturnNonSensitiveNotFlagged() {
	// TC-030: 3 returns, non-sensitive positions must not be flagged
	config := Config{APIKey: "key123", Region: "us-east-1"}
	key, region, err := getAPIKeyRegionErr(config)
	_ = err
	slog.Info("msg", key)    // want "variable \"key\" contains sensitive field \"Config.APIKey\""
	slog.Info("msg", region) // Should NOT be detected
}

func getPasswordAPIKeyName(user User, config Config) (string, string, string) {
	return user.Password, config.APIKey, user.Name
}

func testThreeReturnMultipleSensitive() {
	// TC-031: 3 returns, multiple positions sensitive
	user := User{Name: "iris2", Password: "secret"}
	config := Config{APIKey: "key456", Region: "eu-west-1"}
	password, key, name := getPasswordAPIKeyName(user, config)
	slog.Info("msg", password) // want "variable \"password\" contains sensitive field \"User.Password\""
	slog.Info("msg", key)      // want "variable \"key\" contains sensitive field \"Config.APIKey\""
	slog.Info("msg", name)     // Should NOT be detected
}

func testThreeReturnBlankIdentifiers() {
	// TC-032: Blank identifiers for sensitive positions must not cause errors
	user := User{Name: "jack2", Password: "secret"}
	_, password, err := getNamePasswordErr(user)
	_ = err
	slog.Info("msg", password) // want "variable \"password\" contains sensitive field \"User.Password\""
}

// Negative Test Cases (TC-101 to TC-112)

func testNonSensitiveField() {
	// TC-101: Non-sensitive field
	user := User{Name: "oscar", Password: "secretPQR5"}
	name := user.Name
	slog.Info("msg", "name", name) // Should NOT be detected
}

func testLiteralValue() {
	// TC-102: Literal value
	password := "hardcoded-password"
	slog.Info("msg", "pass", password) // Should NOT be detected
}

func testVariableNotUsedInLogging() {
	// TC-103: Variable not used in logging
	user := User{Name: "paul", Password: "secretSTU6"}
	password := user.Password
	_ = password
	slog.Info("msg", "name", user.Name) // Should NOT be detected
}

func testDifferentScope() {
	// TC-104: Different variable with same name in different scope
	user := User{Name: "quinn", Password: "secretVWX7"}

	func() {
		name := user.Name
		slog.Info("msg", "name", name) // Should NOT be detected
	}()

	func() {
		name := user.Password
		_ = name // Not logged, should NOT be detected
	}()
}

func externalFunc(val string) {
	// This would be in another package in real scenario
	// For this test, we just don't log it
	_ = val
}

func testFunctionFromOtherPackage() {
	// TC-105: Function from other package (out of scope)
	user := User{Name: "rachel", Password: "secretYZ8"}
	password := user.Password
	externalFunc(password) // Should NOT be detected (out of scope)
}

func logMultiple(vals ...string) {
	for _, v := range vals {
		slog.Info("msg", v)
	}
}

func testVariadicArguments() {
	// TC-106: Variadic arguments (out of scope)
	user := User{Name: "sam", Password: "secretABC9"}
	password := user.Password
	logMultiple("safe", password) // Should NOT be detected (variadic out of scope)
}

func logValueSafe(val string) {
	slog.Info("msg", val)
}

func testFunctionUsesSafeValue() {
	// TC-107: Function uses non-sensitive value
	logValueSafe("safe-string") // Should NOT be detected
}

func noLog(val string) {
	// val is not used
	_ = val
	slog.Info("msg", "other", "data")
}

func testParameterNotUsed() {
	// TC-108: Parameter not used in function
	user := User{Name: "tina", Password: "secretDEF0"}
	password := user.Password
	noLog(password) // Should NOT be detected (not logged)
}

func getSafeName(user User) string {
	return user.Name
}

func testFunctionReturningNonSensitive() {
	// TC-111: Function returning non-sensitive value
	user := User{Name: "uma", Password: "secretGHI1"}
	name := getSafeName(user)
	slog.Info("msg", name) // Should NOT be detected
}

func getPasswordNotUsed(user User) string {
	return user.Password
}

func testReturnValueNotUsed() {
	// TC-112: Return value not used
	user := User{Name: "victor", Password: "secretJKL2"}
	getPasswordNotUsed(user)  // Return value not used
	slog.Info("msg", "other") // Should NOT be detected
}

func main() {
	// All test functions
	testBasicAssignmentSlog()
	testAssignmentLog()
	testAssignmentFmt()
	testPointerDereferencing()
	testNestedScope()
	testSlogLoggerMethod()
	testLogLoggerMethod()

	testFunctionCallSamePackage()
	testNestedFunctionCalls()
	testMethodCall()
	testFunctionMultipleParameters()
	testDirectFieldAccessPassedToFunction()
	testFunctionChain3Levels()

	testBasicReturnValue()
	testDirectUseReturnValue()
	testNestedFunctionReturnValue()
	testMethodReturnValue()
	testReturnValueUsedViaVariable()
	testCombinationParameterAndReturn()

	testMultiValueReturnBasic()
	testMultiValueReturnErrNotFlagged()
	testMultiValueReturnBothPositions()
	testMultiValueReturnTwoHop()
	testMultiValueReturnPassToFunction()
	testMultiValueReturnLogPackage()

	testThreeReturnSensitiveAtPosition1()
	testThreeReturnSensitiveAtPosition0()
	testThreeReturnSensitiveAtPosition2()
	testThreeReturnNonSensitiveNotFlagged()
	testThreeReturnMultipleSensitive()
	testThreeReturnBlankIdentifiers()

	testNonSensitiveField()
	testLiteralValue()
	testVariableNotUsedInLogging()
	testDifferentScope()
	testFunctionFromOtherPackage()
	testVariadicArguments()
	testFunctionUsesSafeValue()
	testParameterNotUsed()
	testFunctionReturningNonSensitive()
	testReturnValueNotUsed()
}
