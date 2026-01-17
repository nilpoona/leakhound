package sarif

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/token"
	"go/types"
	"reflect"
	"testing"

	"github.com/nilpoona/leakhound/detector"
	"golang.org/x/tools/go/analysis"
)

func TestNewReporter(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		workDir string
	}{
		{
			name:    "normal initialization",
			workDir: "/home/user/project",
		},
		{
			name:    "empty workDir",
			workDir: "",
		},
	}

	for _, tt := range tests {
		tt := tt // capture range variable
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			pass := &analysis.Pass{}
			writer := &bytes.Buffer{}

			got := NewReporter(pass, writer, tt.workDir)

			if got == nil {
				t.Fatal("NewReporter() returned nil")
			}
			if got.workDir != tt.workDir {
				t.Errorf("NewReporter().workDir = %q, want %q", got.workDir, tt.workDir)
			}
			if got.pass != pass {
				t.Errorf("NewReporter().pass should be the same instance")
			}
			if got.writer != writer {
				t.Errorf("NewReporter().writer should be the same instance")
			}
			if got.version != Version {
				t.Errorf("NewReporter().version = %q, want %q", got.version, Version)
			}
		})
	}
}

func TestReporter_Report(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		findings    []detector.Finding
		setupPass   func() *analysis.Pass
		wantErr     bool
		validateDoc func(t *testing.T, doc *Document)
	}{
		{
			name:     "report with no findings",
			findings: []detector.Finding{},
			setupPass: func() *analysis.Pass {
				return &analysis.Pass{
					Fset: token.NewFileSet(),
				}
			},
			wantErr: false,
			validateDoc: func(t *testing.T, doc *Document) {
				if len(doc.Runs) != 1 {
					t.Errorf("runs count = %d, want 1", len(doc.Runs))
				}
				if len(doc.Runs[0].Results) != 0 {
					t.Errorf("results count = %d, want 0", len(doc.Runs[0].Results))
				}
			},
		},
		{
			name: "report with single finding",
			findings: []detector.Finding{
				{
					Pos:     token.Pos(1),
					Message: "test finding",
					RuleID:  "sensitive-var",
				},
			},
			setupPass: func() *analysis.Pass {
				fset := token.NewFileSet()
				fset.AddFile("/home/user/project/test.go", 1, 100)
				return &analysis.Pass{
					Fset: fset,
				}
			},
			wantErr: false,
			validateDoc: func(t *testing.T, doc *Document) {
				if len(doc.Runs) != 1 {
					t.Fatalf("runs count = %d, want 1", len(doc.Runs))
				}
				if len(doc.Runs[0].Results) != 1 {
					t.Fatalf("results count = %d, want 1", len(doc.Runs[0].Results))
				}

				result := doc.Runs[0].Results[0]
				if result.RuleID != "LH0001" {
					t.Errorf("ruleID = %q, want %q", result.RuleID, "LH0001")
				}
				if result.Message.Text != "test finding" {
					t.Errorf("message = %q, want %q", result.Message.Text, "test finding")
				}
				if result.Level != "error" {
					t.Errorf("level = %q, want %q", result.Level, "error")
				}
			},
		},
		{
			name: "report with multiple findings",
			findings: []detector.Finding{
				{
					Pos:     token.Pos(1),
					Message: "finding 1",
					RuleID:  "sensitive-var",
				},
				{
					Pos:     token.Pos(50),
					Message: "finding 2",
					RuleID:  "sensitive-call",
				},
				{
					Pos:     token.Pos(80),
					Message: "finding 3",
					RuleID:  "sensitive-struct",
				},
			},
			setupPass: func() *analysis.Pass {
				fset := token.NewFileSet()
				fset.AddFile("/home/user/project/test.go", 1, 100)
				return &analysis.Pass{
					Fset: fset,
				}
			},
			wantErr: false,
			validateDoc: func(t *testing.T, doc *Document) {
				if len(doc.Runs[0].Results) != 3 {
					t.Fatalf("results count = %d, want 3", len(doc.Runs[0].Results))
				}

				wantRuleIDs := []string{"LH0001", "LH0002", "LH0003"}
				gotRuleIDs := []string{
					doc.Runs[0].Results[0].RuleID,
					doc.Runs[0].Results[1].RuleID,
					doc.Runs[0].Results[2].RuleID,
				}
				if !reflect.DeepEqual(gotRuleIDs, wantRuleIDs) {
					t.Errorf("ruleIDs = %v, want %v", gotRuleIDs, wantRuleIDs)
				}
			},
		},
		{
			name: "report validates SARIF structure",
			findings: []detector.Finding{
				{
					Pos:     token.Pos(1),
					Message: "test",
					RuleID:  "sensitive-field",
				},
			},
			setupPass: func() *analysis.Pass {
				fset := token.NewFileSet()
				fset.AddFile("/home/user/project/test.go", 1, 100)
				return &analysis.Pass{
					Fset: fset,
				}
			},
			wantErr: false,
			validateDoc: func(t *testing.T, doc *Document) {
				if doc.Version != "2.1.0" {
					t.Errorf("version = %q, want %q", doc.Version, "2.1.0")
				}
				if doc.Schema == "" {
					t.Error("schema should not be empty")
				}

				run := doc.Runs[0]
				if run.Tool.Driver.Name != "leakhound" {
					t.Errorf("tool name = %q, want %q", run.Tool.Driver.Name, "leakhound")
				}
				if len(run.Tool.Driver.Rules) != 4 {
					t.Errorf("rules count = %d, want 4", len(run.Tool.Driver.Rules))
				}

				wantAutomation := &AutomationDetails{
					ID: "leakhound/analysis",
				}
				if !reflect.DeepEqual(run.AutomationDetails, wantAutomation) {
					t.Errorf("automation details = %+v, want %+v", run.AutomationDetails, wantAutomation)
				}
			},
		},
		{
			name: "report with all rule types",
			findings: []detector.Finding{
				{Pos: token.Pos(1), Message: "var", RuleID: "sensitive-var"},
				{Pos: token.Pos(2), Message: "call", RuleID: "sensitive-call"},
				{Pos: token.Pos(3), Message: "struct", RuleID: "sensitive-struct"},
				{Pos: token.Pos(4), Message: "field", RuleID: "sensitive-field"},
			},
			setupPass: func() *analysis.Pass {
				fset := token.NewFileSet()
				fset.AddFile("/home/user/project/test.go", 1, 100)
				return &analysis.Pass{
					Fset: fset,
				}
			},
			wantErr: false,
			validateDoc: func(t *testing.T, doc *Document) {
				wantRuleIDs := []string{"LH0001", "LH0002", "LH0003", "LH0004"}
				gotRuleIDs := make([]string, len(doc.Runs[0].Results))
				for i, r := range doc.Runs[0].Results {
					gotRuleIDs[i] = r.RuleID
				}
				if !reflect.DeepEqual(gotRuleIDs, wantRuleIDs) {
					t.Errorf("ruleIDs = %v, want %v", gotRuleIDs, wantRuleIDs)
				}
			},
		},
	}

	for _, tt := range tests {
		tt := tt // capture range variable
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			pass := tt.setupPass()
			var buf bytes.Buffer
			reporter := NewReporter(pass, &buf, "/home/user/project")

			err := reporter.Report(tt.findings)

			if (err != nil) != tt.wantErr {
				t.Errorf("Report() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				var doc Document
				if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
					t.Fatalf("Failed to parse SARIF JSON: %v", err)
				}

				if tt.validateDoc != nil {
					tt.validateDoc(t, &doc)
				}
			}
		})
	}
}

func TestReporter_ReportValidJSON(t *testing.T) {
	t.Parallel()

	fset := token.NewFileSet()
	fset.AddFile("/home/user/project/test.go", 1, 100)

	pass := &analysis.Pass{
		Fset: fset,
	}

	findings := []detector.Finding{
		{
			Pos:     token.Pos(1),
			Message: "test finding",
			RuleID:  "sensitive-var",
		},
	}

	var buf bytes.Buffer
	reporter := NewReporter(pass, &buf, "/home/user/project")

	if err := reporter.Report(findings); err != nil {
		t.Fatalf("Report() failed: %v", err)
	}

	// Verify JSON is valid
	var doc Document
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("Invalid JSON output: %v", err)
	}

	// Verify pretty printing (indentation)
	jsonStr := buf.String()
	if !bytes.Contains([]byte(jsonStr), []byte("\n  ")) {
		t.Error("JSON should be indented")
	}
}

func TestReporter_RelativePaths(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		workDir  string
		filePath string
		wantURI  string
	}{
		{
			name:     "file in subdirectory",
			workDir:  "/home/user/project",
			filePath: "/home/user/project/internal/test.go",
			wantURI:  "internal/test.go",
		},
		{
			name:     "file in root",
			workDir:  "/home/user/project",
			filePath: "/home/user/project/main.go",
			wantURI:  "main.go",
		},
		{
			name:     "file outside workDir",
			workDir:  "/home/user/project",
			filePath: "/other/location/test.go",
			wantURI:  "../../../other/location/test.go",
		},
		{
			name:     "deeply nested file",
			workDir:  "/home/user/project",
			filePath: "/home/user/project/pkg/internal/detector/test.go",
			wantURI:  "pkg/internal/detector/test.go",
		},
	}

	for _, tt := range tests {
		tt := tt // capture range variable
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			fset := token.NewFileSet()
			fset.AddFile(tt.filePath, 1, 100)

			pass := &analysis.Pass{
				Fset: fset,
			}

			findings := []detector.Finding{
				{
					Pos:     token.Pos(1),
					Message: "test",
					RuleID:  "sensitive-var",
				},
			}

			var buf bytes.Buffer
			reporter := NewReporter(pass, &buf, tt.workDir)

			if err := reporter.Report(findings); err != nil {
				t.Fatalf("Report() failed: %v", err)
			}

			var doc Document
			if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
				t.Fatalf("Failed to parse SARIF JSON: %v", err)
			}

			result := doc.Runs[0].Results[0]
			gotLoc := result.Locations[0].PhysicalLocation.ArtifactLocation
			wantLoc := ArtifactLocation{
				URI:       tt.wantURI,
				URIBaseID: "%SRCROOT%",
			}

			if !reflect.DeepEqual(gotLoc, wantLoc) {
				t.Errorf("artifact location = %+v, want %+v", gotLoc, wantLoc)
			}
		})
	}
}

func TestReporter_Fingerprints(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		findings    []detector.Finding
		wantSameFor []int // indices of findings that should have same fingerprint
	}{
		{
			name: "same location same rule produces same fingerprint",
			findings: []detector.Finding{
				{Pos: token.Pos(1), Message: "msg1", RuleID: "sensitive-var"},
				{Pos: token.Pos(1), Message: "msg2", RuleID: "sensitive-var"},
			},
			wantSameFor: []int{0, 1},
		},
		{
			name: "different location produces different fingerprint",
			findings: []detector.Finding{
				{Pos: token.Pos(1), Message: "msg1", RuleID: "sensitive-var"},  // Line 1
				{Pos: token.Pos(25), Message: "msg2", RuleID: "sensitive-var"}, // Line 2 (after AddLine(20))
			},
			wantSameFor: nil,
		},
		{
			name: "different rule produces different fingerprint",
			findings: []detector.Finding{
				{Pos: token.Pos(1), Message: "msg1", RuleID: "sensitive-var"},
				{Pos: token.Pos(1), Message: "msg2", RuleID: "sensitive-field"},
			},
			wantSameFor: nil,
		},
	}

	for _, tt := range tests {
		tt := tt // capture range variable
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			fset := token.NewFileSet()
			file := fset.AddFile("/home/user/project/test.go", 1, 100)
			// Add line breaks to support multiple lines
			file.AddLine(20) // Line 2 starts at position 20
			file.AddLine(40) // Line 3 starts at position 40

			pass := &analysis.Pass{
				Fset: fset,
			}

			var buf bytes.Buffer
			reporter := NewReporter(pass, &buf, "/home/user/project")

			if err := reporter.Report(tt.findings); err != nil {
				t.Fatalf("Report() failed: %v", err)
			}

			var doc Document
			if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
				t.Fatalf("Failed to parse SARIF JSON: %v", err)
			}

			// Verify all results have fingerprints
			for i, result := range doc.Runs[0].Results {
				if result.PartialFingerprints == nil {
					t.Errorf("result[%d] PartialFingerprints should not be nil", i)
				}
				hash, ok := result.PartialFingerprints["primaryLocationLineHash"]
				if !ok {
					t.Errorf("result[%d] primaryLocationLineHash should be present", i)
				}
				if len(hash) != 32 {
					t.Errorf("result[%d] fingerprint hash length = %d, want 32", i, len(hash))
				}
			}

			// Verify same fingerprints for specified indices
			if len(tt.wantSameFor) == 2 {
				hash1 := doc.Runs[0].Results[tt.wantSameFor[0]].PartialFingerprints["primaryLocationLineHash"]
				hash2 := doc.Runs[0].Results[tt.wantSameFor[1]].PartialFingerprints["primaryLocationLineHash"]
				if hash1 != hash2 {
					t.Errorf("fingerprints should be same for indices %v, got %q and %q",
						tt.wantSameFor, hash1, hash2)
				}
			} else if len(doc.Runs[0].Results) == 2 {
				// Verify different fingerprints
				hash1 := doc.Runs[0].Results[0].PartialFingerprints["primaryLocationLineHash"]
				hash2 := doc.Runs[0].Results[1].PartialFingerprints["primaryLocationLineHash"]
				if hash1 == hash2 {
					t.Error("fingerprints should be different but got same hash")
				}
			}
		})
	}
}

func TestReporter_VersionHandling(t *testing.T) {
	t.Parallel()

	fset := token.NewFileSet()
	fset.AddFile("/home/user/project/test.go", 1, 100)

	pass := &analysis.Pass{
		Fset: fset,
	}

	findings := []detector.Finding{
		{Pos: token.Pos(1), Message: "test", RuleID: "sensitive-var"},
	}

	// Test that version is captured at reporter creation time
	var buf bytes.Buffer
	reporter := NewReporter(pass, &buf, "/home/user/project")

	if err := reporter.Report(findings); err != nil {
		t.Fatalf("Report() failed: %v", err)
	}

	var doc Document
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("Failed to parse SARIF JSON: %v", err)
	}

	gotVersion := doc.Runs[0].Tool.Driver.Version
	// Version should be set (either from global Version or "dev")
	if gotVersion == "" {
		t.Error("version should not be empty")
	}
	if gotVersion != Version && gotVersion != "dev" {
		t.Errorf("version = %q, want %q or %q", gotVersion, Version, "dev")
	}

	gotSemVer := doc.Runs[0].Tool.Driver.SemanticVersion
	if gotSemVer != gotVersion {
		t.Errorf("semanticVersion = %q, want %q (should match version)", gotSemVer, gotVersion)
	}
}

func TestReporter_EmptyVersionFallback(t *testing.T) {
	t.Parallel()

	fset := token.NewFileSet()
	fset.AddFile("/home/user/project/test.go", 1, 100)

	pass := &analysis.Pass{
		Fset: fset,
	}

	findings := []detector.Finding{
		{Pos: token.Pos(1), Message: "test", RuleID: "sensitive-var"},
	}

	var buf bytes.Buffer
	// Create reporter with empty version by directly constructing
	reporter := &Reporter{
		pass:    pass,
		writer:  &buf,
		workDir: "/home/user/project",
		version: "", // Empty version should fall back to "dev"
	}

	if err := reporter.Report(findings); err != nil {
		t.Fatalf("Report() failed: %v", err)
	}

	var doc Document
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("Failed to parse SARIF JSON: %v", err)
	}

	wantVersion := "dev"
	gotVersion := doc.Runs[0].Tool.Driver.Version
	if gotVersion != wantVersion {
		t.Errorf("version = %q, want %q", gotVersion, wantVersion)
	}

	gotSemVer := doc.Runs[0].Tool.Driver.SemanticVersion
	if gotSemVer != wantVersion {
		t.Errorf("semanticVersion = %q, want %q", gotSemVer, wantVersion)
	}
}

func TestReporter_CompletePass(t *testing.T) {
	t.Parallel()

	// Create a more complete Pass structure
	fset := token.NewFileSet()
	file := fset.AddFile("/home/user/project/test.go", 1, 100)

	pass := &analysis.Pass{
		Fset: fset,
		Files: []*ast.File{
			{
				Name: &ast.Ident{Name: "test"},
			},
		},
		TypesInfo: &types.Info{},
		Pkg:       types.NewPackage("test/pkg", "pkg"),
	}

	findings := []detector.Finding{
		{
			Pos:     file.Pos(10),
			Message: "sensitive data logged",
			RuleID:  "sensitive-var",
		},
	}

	var buf bytes.Buffer
	reporter := NewReporter(pass, &buf, "/home/user/project")

	if err := reporter.Report(findings); err != nil {
		t.Fatalf("Report() failed: %v", err)
	}

	var doc Document
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("Failed to parse SARIF JSON: %v", err)
	}

	if len(doc.Runs) != 1 {
		t.Errorf("runs count = %d, want 1", len(doc.Runs))
	}
	if len(doc.Runs[0].Results) != 1 {
		t.Errorf("results count = %d, want 1", len(doc.Runs[0].Results))
	}
}
