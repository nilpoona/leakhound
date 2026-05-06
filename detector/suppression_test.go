package detector

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/nilpoona/leakhound/config"
)

func TestParseNoleak(t *testing.T) {
	tests := []struct {
		name     string
		text     string
		wantRule string
		wantOK   bool
	}{
		{"valid single rule", "//noleak:LH0001", "LH0001", true},
		{"valid all", "//noleak:all", "all", true},
		{"trailing text ignored", "//noleak:LH0003 intentionally safe", "LH0003", true},
		{"trailing tab ignored", "//noleak:LH0002\ttab after", "LH0002", true},
		{"space prefix invalid", "// noleak:LH0001", "", false},
		{"empty rule ID", "//noleak:", "", false},
		{"no noleak prefix", "// normal comment", "", false},
		{"noleak without colon", "//noleak", "", false},
		{"unknown ID accepted", "//noleak:INVALID", "INVALID", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseNoleak(tt.text)
			if ok != tt.wantOK {
				t.Errorf("parseNoleak(%q) ok = %v, want %v", tt.text, ok, tt.wantOK)
			}
			if got != tt.wantRule {
				t.Errorf("parseNoleak(%q) rule = %q, want %q", tt.text, got, tt.wantRule)
			}
		})
	}
}

func TestSuppressionFilterApply_ConfigRules(t *testing.T) {
	fset := token.NewFileSet()

	findings := []Finding{
		{Pos: token.NoPos, Message: "struct leak", RuleID: RuleIDSensitiveStruct},
		{Pos: token.NoPos, Message: "field leak", RuleID: RuleIDSensitiveField},
	}

	cfg := &config.Config{
		Suppress: config.SuppressConfig{
			Rules: []string{"LH0003"}, // suppress struct rule
		},
	}

	sf := &SuppressionFilter{}
	sf.Build([]*ast.File{}, fset)
	result := sf.Apply(findings, fset, cfg)

	if !result[0].Suppressed {
		t.Error("finding with RuleIDSensitiveStruct (LH0003) should be suppressed by config rule")
	}
	if result[0].SuppressionKind != "external" {
		t.Errorf("config suppression kind = %q, want %q", result[0].SuppressionKind, "external")
	}
	if result[1].Suppressed {
		t.Error("finding with RuleIDSensitiveField (LH0004) should not be suppressed")
	}
}

func TestSuppressionFilterApply_NoSuppressions(t *testing.T) {
	fset := token.NewFileSet()

	findings := []Finding{
		{Pos: token.NoPos, Message: "field leak", RuleID: RuleIDSensitiveField},
	}

	cfg := &config.Config{}

	sf := &SuppressionFilter{}
	sf.Build([]*ast.File{}, fset)
	result := sf.Apply(findings, fset, cfg)

	if result[0].Suppressed {
		t.Error("finding should not be suppressed when no rules are configured")
	}
}

func TestSuppressionFilterApply_SameLine(t *testing.T) {
	// line 2: no comment → not suppressed
	// line 3: same-line //noleak → suppressed
	// line 6: comment is 3 lines above → not suppressed
	src := "package p\n" + // 1
		"var _ = 1\n" + // 2  no comment
		"var _ = 2 //noleak:LH0003\n" + // 3  same-line
		"var _ = 3\n" + // 4  preceded by line 3 comment (also suppressed — expected side-effect)
		"\n" + // 5
		"var _ = 4\n" // 6  comment on line 3 is 3 lines away → not suppressed

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "test.go", src, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}

	tf := fset.File(file.Pos())
	findings := []Finding{
		{Pos: tf.LineStart(2), RuleID: RuleIDSensitiveStruct},
		{Pos: tf.LineStart(3), RuleID: RuleIDSensitiveStruct},
		{Pos: tf.LineStart(6), RuleID: RuleIDSensitiveStruct},
	}

	sf := &SuppressionFilter{}
	sf.Build([]*ast.File{file}, fset)
	result := sf.Apply(findings, fset, &config.Config{})

	if result[0].Suppressed {
		t.Error("finding on line 2 should not be suppressed (no comment on lines 1-2)")
	}
	if !result[1].Suppressed {
		t.Error("finding on line 3 should be suppressed by same-line //noleak comment")
	}
	if result[1].SuppressionKind != "inSource" {
		t.Errorf("suppression kind = %q, want %q", result[1].SuppressionKind, "inSource")
	}
	if result[2].Suppressed {
		t.Error("finding on line 6 should not be suppressed: comment on line 3 is 3 lines above")
	}
}

func TestSuppressionFilterApply_PrecedingLine(t *testing.T) {
	// line 3: //noleak:LH0003
	// line 4: finding → suppressed (comment is line-1)
	// line 6: //noleak:LH0003
	// line 7: blank-ish statement
	// line 8: finding → NOT suppressed (comment is line-2)
	src := "package p\n" + // 1
		"\n" + // 2
		"//noleak:LH0003\n" + // 3
		"var _ = 1\n" + // 4  ← suppressed
		"\n" + // 5
		"//noleak:LH0003\n" + // 6
		"var _ = 2\n" + // 7
		"var _ = 3\n" // 8  ← NOT suppressed (comment 2 lines above)

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "test.go", src, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}

	tf := fset.File(file.Pos())
	findings := []Finding{
		{Pos: tf.LineStart(4), RuleID: RuleIDSensitiveStruct},
		{Pos: tf.LineStart(8), RuleID: RuleIDSensitiveStruct},
	}

	sf := &SuppressionFilter{}
	sf.Build([]*ast.File{file}, fset)
	result := sf.Apply(findings, fset, &config.Config{})

	if !result[0].Suppressed {
		t.Error("finding on line 4 should be suppressed by comment on line 3 (line-1)")
	}
	if result[0].SuppressionKind != "inSource" {
		t.Errorf("suppression kind = %q, want %q", result[0].SuppressionKind, "inSource")
	}
	if result[1].Suppressed {
		t.Error("finding on line 8 should NOT be suppressed: //noleak comment is 2 lines above")
	}
}

func TestSuppressionFilterBuild_MultipleFiles(t *testing.T) {
	src1 := "package p\nvar _ = 1 //noleak:LH0003\n"
	src2 := "package p\nvar _ = 2 //noleak:LH0004\n"

	fset := token.NewFileSet()
	file1, err := parser.ParseFile(fset, "file1.go", src1, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	file2, err := parser.ParseFile(fset, "file2.go", src2, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}

	tf1 := fset.File(file1.Pos())
	tf2 := fset.File(file2.Pos())
	findings := []Finding{
		{Pos: tf1.LineStart(2), RuleID: RuleIDSensitiveStruct}, // file1 line 2 → LH0003
		{Pos: tf2.LineStart(2), RuleID: RuleIDSensitiveField},  // file2 line 2 → LH0004
		{Pos: tf1.LineStart(2), RuleID: RuleIDSensitiveField},  // file1 line 2 with LH0004 → NOT suppressed
	}

	sf := &SuppressionFilter{}
	sf.Build([]*ast.File{file1, file2}, fset)
	result := sf.Apply(findings, fset, &config.Config{})

	if !result[0].Suppressed {
		t.Error("finding in file1 should be suppressed by file1's //noleak:LH0003")
	}
	if !result[1].Suppressed {
		t.Error("finding in file2 should be suppressed by file2's //noleak:LH0004")
	}
	if result[2].Suppressed {
		t.Error("finding in file1 with wrong rule ID (LH0004) should NOT be suppressed")
	}
}

func TestSuppressionFilterApply_MultipleRulesNearSameLine(t *testing.T) {
	// line 2: //noleak:LH0003   (preceding-line comment)
	// line 3: var _ //noleak:LH0004  (same-line comment)
	// Finding with LH0003 on line 3 → suppressed by preceding line (line 2)
	// Finding with LH0004 on line 3 → suppressed by same line (line 3)
	// Finding with LH0001 on line 3 → NOT suppressed (no match on lines 2 or 3)
	src := "package p\n" +
		"//noleak:LH0003\n" +
		"var _ = 1 //noleak:LH0004\n"

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "test.go", src, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}

	tf := fset.File(file.Pos())
	line3 := tf.LineStart(3)
	findings := []Finding{
		{Pos: line3, RuleID: RuleIDSensitiveStruct}, // LH0003 — matched by preceding line 2
		{Pos: line3, RuleID: RuleIDSensitiveField},  // LH0004 — matched by same line 3
		{Pos: line3, RuleID: RuleIDSensitiveVar},    // LH0001 — no match
	}

	sf := &SuppressionFilter{}
	sf.Build([]*ast.File{file}, fset)
	result := sf.Apply(findings, fset, &config.Config{})

	if !result[0].Suppressed {
		t.Error("LH0003 finding on line 3 should be suppressed by preceding-line comment")
	}
	if !result[1].Suppressed {
		t.Error("LH0004 finding on line 3 should be suppressed by same-line comment")
	}
	if result[2].Suppressed {
		t.Error("LH0001 finding on line 3 should NOT be suppressed (no matching noleak comment)")
	}
}

func TestSuppressionFilterApply_Idempotent(t *testing.T) {
	src := "package p\nvar _ = 1 //noleak:LH0003\n"

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "test.go", src, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}

	tf := fset.File(file.Pos())
	findings := []Finding{
		{Pos: tf.LineStart(2), RuleID: RuleIDSensitiveStruct},
	}

	sf := &SuppressionFilter{}
	sf.Build([]*ast.File{file}, fset)

	result := sf.Apply(findings, fset, &config.Config{})
	if !result[0].Suppressed {
		t.Fatal("finding should be suppressed on first Apply")
	}

	// Second Apply on the already-suppressed slice must not corrupt state
	result2 := sf.Apply(result, fset, &config.Config{})
	if !result2[0].Suppressed {
		t.Error("finding should remain suppressed after second Apply call")
	}
	if result2[0].SuppressionKind != "inSource" {
		t.Errorf("suppression kind after second Apply = %q, want %q", result2[0].SuppressionKind, "inSource")
	}
}

func TestSuppressionFilterApply_ConfigTakesPriorityOverInline(t *testing.T) {
	// The same finding is covered by both a config rule and an inline comment.
	// Config is checked first → kind must be "external".
	src := "package p\nvar _ = 1 //noleak:LH0003\n"

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "test.go", src, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}

	tf := fset.File(file.Pos())
	findings := []Finding{
		{Pos: tf.LineStart(2), RuleID: RuleIDSensitiveStruct},
	}

	cfg := &config.Config{
		Suppress: config.SuppressConfig{Rules: []string{"LH0003"}},
	}

	sf := &SuppressionFilter{}
	sf.Build([]*ast.File{file}, fset)
	result := sf.Apply(findings, fset, cfg)

	if !result[0].Suppressed {
		t.Error("finding should be suppressed")
	}
	if result[0].SuppressionKind != "external" {
		t.Errorf("suppression kind = %q, want %q (config takes priority over inline)", result[0].SuppressionKind, "external")
	}
}

func TestSuppressionFilterApply_AllConfigRules(t *testing.T) {
	fset := token.NewFileSet()

	findings := []Finding{
		{Pos: token.NoPos, Message: "var leak", RuleID: RuleIDSensitiveVar},
		{Pos: token.NoPos, Message: "call leak", RuleID: RuleIDSensitiveCall},
		{Pos: token.NoPos, Message: "struct leak", RuleID: RuleIDSensitiveStruct},
		{Pos: token.NoPos, Message: "field leak", RuleID: RuleIDSensitiveField},
	}

	cfg := &config.Config{
		Suppress: config.SuppressConfig{
			Rules: []string{"LH0001", "LH0002", "LH0003", "LH0004"},
		},
	}

	sf := &SuppressionFilter{}
	sf.Build([]*ast.File{}, fset)
	result := sf.Apply(findings, fset, cfg)

	for _, f := range result {
		if !f.Suppressed {
			t.Errorf("finding %q should be suppressed", f.RuleID)
		}
		if f.SuppressionKind != "external" {
			t.Errorf("finding %q suppression kind = %q, want %q", f.RuleID, f.SuppressionKind, "external")
		}
	}
}
