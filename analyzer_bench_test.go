package leakhound_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"testing"

	"github.com/nilpoona/leakhound"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
)

// BenchmarkSmallCodebase benchmarks the analyzer on a small codebase (~100 lines)
func BenchmarkSmallCodebase(b *testing.B) {
	src := `package main

import "log/slog"

type User struct {
	Name     string
	Password string ` + "`sensitive:\"true\"`" + `
}

func main() {
	user := User{Name: "alice", Password: "secret123"}

	// Direct field access
	slog.Info("msg", "pass", user.Password)

	// Variable assignment
	password := user.Password
	slog.Info("msg", "pass", password)

	// Function call
	logValue(password)
}

func logValue(val string) {
	slog.Info("msg", val)
}
`

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		runAnalyzerOnSource(b, src)
	}
}

// BenchmarkMediumCodebase benchmarks the analyzer on a medium codebase (~500 lines)
func BenchmarkMediumCodebase(b *testing.B) {
	// Generate a more complex codebase with multiple functions and types
	src := generateMediumCodebase()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		runAnalyzerOnSource(b, src)
	}
}

func runAnalyzerOnSource(b *testing.B, src string) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "test.go", src, 0)
	if err != nil {
		b.Fatal(err)
	}

	// Create type checker
	config := &types.Config{
		Importer: nil, // Basic importer for testing
	}
	info := &types.Info{
		Types: make(map[ast.Expr]types.TypeAndValue),
		Defs:  make(map[*ast.Ident]types.Object),
		Uses:  make(map[*ast.Ident]types.Object),
	}
	pkg, _ := config.Check("test", fset, []*ast.File{file}, info)

	// Create analysis pass
	pass := &analysis.Pass{
		Analyzer:          leakhound.Analyzer,
		Fset:              fset,
		Files:             []*ast.File{file},
		Pkg:               pkg,
		TypesInfo:         info,
		Report:            func(analysis.Diagnostic) {},
		ResultOf:          make(map[*analysis.Analyzer]interface{}),
		ImportObjectFact:  func(types.Object, analysis.Fact) bool { return false },
		ImportPackageFact: func(*types.Package, analysis.Fact) bool { return false },
		ExportObjectFact:  func(types.Object, analysis.Fact) {},
		ExportPackageFact: func(analysis.Fact) {},
		AllObjectFacts:    func() []analysis.ObjectFact { return nil },
		AllPackageFacts:   func() []analysis.PackageFact { return nil },
	}

	// Run inspect analyzer first
	inspectResult, err := inspect.Analyzer.Run(pass)
	if err != nil {
		b.Fatal(err)
	}
	pass.ResultOf[inspect.Analyzer] = inspectResult

	// Run our analyzer
	_, err = leakhound.Analyzer.Run(pass)
	if err != nil {
		b.Fatal(err)
	}
}

func generateMediumCodebase() string {
	return `package main

import (
	"context"
	"log"
	"log/slog"
	"fmt"
)

type User struct {
	ID       int
	Name     string
	Email    string
	Password string ` + "`sensitive:\"true\"`" + `
	APIToken string ` + "`sensitive:\"true\"`" + `
}

type Config struct {
	AppName  string
	Version  string
	Secret   string ` + "`sensitive:\"true\"`" + `
	DBConfig DatabaseConfig
}

type DatabaseConfig struct {
	Host     string
	Port     int
	Username string
	Password string ` + "`sensitive:\"true\"`" + `
}

func main() {
	user := User{
		ID:       1,
		Name:     "Alice",
		Email:    "alice@example.com",
		Password: "secret123",
		APIToken: "token456",
	}

	config := Config{
		AppName: "MyApp",
		Version: "1.0.0",
		Secret:  "appsecret",
		DBConfig: DatabaseConfig{
			Host:     "localhost",
			Port:     5432,
			Username: "admin",
			Password: "dbpassword",
		},
	}

	// Direct logging
	slog.Info("user created", "name", user.Name)
	slog.Info("config loaded", "app", config.AppName)

	// Variable assignments
	password := user.Password
	token := user.APIToken
	secret := config.Secret

	// Function calls with sensitive data
	logUserInfo(user)
	processPassword(password)
	validateToken(token)
	checkSecret(secret)

	// Nested function calls
	outerFunc(password)

	// Return value tracking
	pwd := getPassword(user)
	fmt.Println("got password:", pwd)

	// Multiple levels of nesting
	level1(user.Password)
}

func logUserInfo(u User) {
	slog.Info("user info", "id", u.ID, "name", u.Name)
}

func processPassword(pwd string) {
	log.Println("processing:", pwd)
}

func validateToken(token string) {
	slog.Info("validating", "token", token)
}

func checkSecret(s string) {
	fmt.Printf("secret: %s\n", s)
}

func outerFunc(val string) {
	innerFunc(val)
}

func innerFunc(val string) {
	slog.Info("inner", "val", val)
}

func getPassword(u User) string {
	return u.Password
}

func level1(v string) {
	level2(v)
}

func level2(v string) {
	level3(v)
}

func level3(v string) {
	slog.Info("level3", "v", v)
}

func authenticateUser(username, password string) bool {
	log.Printf("auth attempt: %s", username)
	return password == "correctpassword"
}

func createSession(userID int, token string) {
	slog.Info("session created", "user", userID)
	fmt.Println("token:", token)
}

func updateConfig(c Config) {
	slog.Info("updating config", "app", c.AppName)
	log.Println("config:", c)
}

func logDatabaseConnection(db DatabaseConfig) {
	slog.Info("db connection", "host", db.Host, "port", db.Port)
	log.Printf("db config: %+v", db)
}
`
}
