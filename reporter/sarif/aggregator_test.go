package sarif

import (
	"bytes"
	"encoding/json"
	"go/token"
	"reflect"
	"testing"

	"github.com/nilpoona/leakhound/detector"
)

func TestNewAggregatingReporter(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args string
		want *AggregatingReporter
	}{
		{
			name: "normal workDir",
			args: "/home/user/project",
			want: &AggregatingReporter{
				workDir:  "/home/user/project",
				findings: []FindingWithFset{},
				version:  Version,
			},
		},
		{
			name: "empty workDir",
			args: "",
			want: &AggregatingReporter{
				workDir:  "",
				findings: []FindingWithFset{},
				version:  Version,
			},
		},
		{
			name: "relative workDir",
			args: "./project",
			want: &AggregatingReporter{
				workDir:  "./project",
				findings: []FindingWithFset{},
				version:  Version,
			},
		},
	}

	for _, tt := range tests {
		tt := tt // capture range variable
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := NewAggregatingReporter(tt.args)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewAggregatingReporter() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestAggregatingReporter_AddFindings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		workDir       string
		findings      []detector.Finding
		expectedCount int
		callCount     int // Number of times to call AddFindings
	}{
		{
			name:    "add single finding",
			workDir: "/home/user/project",
			findings: []detector.Finding{
				{
					Pos:     token.Pos(1),
					Message: "test finding",
					RuleID:  "sensitive-var",
				},
			},
			expectedCount: 1,
			callCount:     1,
		},
		{
			name:    "add multiple findings",
			workDir: "/home/user/project",
			findings: []detector.Finding{
				{
					Pos:     token.Pos(1),
					Message: "finding 1",
					RuleID:  "sensitive-var",
				},
				{
					Pos:     token.Pos(2),
					Message: "finding 2",
					RuleID:  "sensitive-field",
				},
				{
					Pos:     token.Pos(3),
					Message: "finding 3",
					RuleID:  "sensitive-struct",
				},
			},
			expectedCount: 3,
			callCount:     1,
		},
		{
			name:          "add empty findings",
			workDir:       "/home/user/project",
			findings:      []detector.Finding{},
			expectedCount: 0,
			callCount:     1,
		},
		{
			name:    "add findings multiple times",
			workDir: "/home/user/project",
			findings: []detector.Finding{
				{
					Pos:     token.Pos(1),
					Message: "finding",
					RuleID:  "sensitive-var",
				},
			},
			expectedCount: 3, // Called 3 times with 1 finding each
			callCount:     3,
		},
	}

	for _, tt := range tests {
		tt := tt // capture range variable
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			reporter := NewAggregatingReporter(tt.workDir)
			fset := token.NewFileSet()

			for i := 0; i < tt.callCount; i++ {
				reporter.AddFindings(tt.findings, fset)
			}

			if len(reporter.findings) != tt.expectedCount {
				t.Errorf("findings count = %d, want %d", len(reporter.findings), tt.expectedCount)
			}

			// Verify each finding has correct fset
			for i, f := range reporter.findings {
				if f.Fset != fset {
					t.Errorf("finding[%d].Fset does not match expected FileSet", i)
				}
			}
		})
	}
}

func TestAggregatingReporter_Report(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		workDir     string
		findings    []detector.Finding
		setupFset   func() *token.FileSet
		wantErr     bool
		validateDoc func(t *testing.T, doc *Document)
	}{
		{
			name:     "report with no findings",
			workDir:  "/home/user/project",
			findings: []detector.Finding{},
			setupFset: func() *token.FileSet {
				return token.NewFileSet()
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
			name:    "report with single finding",
			workDir: "/home/user/project",
			findings: []detector.Finding{
				{
					Pos:     token.Pos(1),
					Message: "test finding",
					RuleID:  "sensitive-var",
				},
			},
			setupFset: func() *token.FileSet {
				fset := token.NewFileSet()
				fset.AddFile("/home/user/project/test.go", 1, 100)
				return fset
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
				want := Result{
					RuleID: "LH0001",
					Message: Message{
						Text: "test finding",
					},
					Level: "error",
					Locations: []Location{
						{
							PhysicalLocation: PhysicalLocation{
								ArtifactLocation: ArtifactLocation{
									URI:       "test.go",
									URIBaseID: "%SRCROOT%",
								},
								Region: Region{
									StartLine:   1,
									StartColumn: 1,
								},
							},
						},
					},
					PartialFingerprints: result.PartialFingerprints, // Copy fingerprints for comparison
				}

				if !reflect.DeepEqual(result, want) {
					t.Errorf("result mismatch\ngot:  %+v\nwant: %+v", result, want)
				}
			},
		},
		{
			name:    "report with multiple findings",
			workDir: "/home/user/project",
			findings: []detector.Finding{
				{
					Pos:     token.Pos(1),
					Message: "finding 1",
					RuleID:  "sensitive-var",
				},
				{
					Pos:     token.Pos(50),
					Message: "finding 2",
					RuleID:  "sensitive-field",
				},
			},
			setupFset: func() *token.FileSet {
				fset := token.NewFileSet()
				fset.AddFile("/home/user/project/test.go", 1, 100)
				return fset
			},
			wantErr: false,
			validateDoc: func(t *testing.T, doc *Document) {
				if len(doc.Runs[0].Results) != 2 {
					t.Fatalf("results count = %d, want 2", len(doc.Runs[0].Results))
				}

				wantRuleIDs := []string{"LH0001", "LH0004"}
				gotRuleIDs := []string{
					doc.Runs[0].Results[0].RuleID,
					doc.Runs[0].Results[1].RuleID,
				}
				if !reflect.DeepEqual(gotRuleIDs, wantRuleIDs) {
					t.Errorf("ruleIDs = %v, want %v", gotRuleIDs, wantRuleIDs)
				}
			},
		},
		{
			name:    "report validates SARIF structure",
			workDir: "/home/user/project",
			findings: []detector.Finding{
				{
					Pos:     token.Pos(1),
					Message: "test",
					RuleID:  "sensitive-var",
				},
			},
			setupFset: func() *token.FileSet {
				fset := token.NewFileSet()
				fset.AddFile("/home/user/project/test.go", 1, 100)
				return fset
			},
			wantErr: false,
			validateDoc: func(t *testing.T, doc *Document) {
				if doc.Version != "2.1.0" {
					t.Errorf("version = %q, want %q", doc.Version, "2.1.0")
				}
				if doc.Schema == "" {
					t.Error("schema should not be empty")
				}
				if len(doc.Runs) != 1 {
					t.Fatalf("runs count = %d, want 1", len(doc.Runs))
				}

				run := doc.Runs[0]
				if run.Tool.Driver.Name != "leakhound" {
					t.Errorf("tool name = %q, want %q", run.Tool.Driver.Name, "leakhound")
				}
				if len(run.Tool.Driver.Rules) != 4 {
					t.Errorf("rules count = %d, want 4", len(run.Tool.Driver.Rules))
				}
				if run.AutomationDetails == nil {
					t.Error("automation details should not be nil")
				}

				wantAutomation := &AutomationDetails{
					ID: "leakhound/analysis",
				}
				if !reflect.DeepEqual(run.AutomationDetails, wantAutomation) {
					t.Errorf("automation details = %+v, want %+v", run.AutomationDetails, wantAutomation)
				}
			},
		},
	}

	for _, tt := range tests {
		tt := tt // capture range variable
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			reporter := NewAggregatingReporter(tt.workDir)
			fset := tt.setupFset()

			reporter.AddFindings(tt.findings, fset)

			var buf bytes.Buffer
			err := reporter.Report(&buf)

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

func TestAggregatingReporter_ReportValidJSON(t *testing.T) {
	t.Parallel()

	reporter := NewAggregatingReporter("/home/user/project")
	fset := token.NewFileSet()
	fset.AddFile("/home/user/project/test.go", 1, 100)

	findings := []detector.Finding{
		{
			Pos:     token.Pos(1),
			Message: "test finding",
			RuleID:  "sensitive-var",
		},
	}

	reporter.AddFindings(findings, fset)

	var buf bytes.Buffer
	if err := reporter.Report(&buf); err != nil {
		t.Fatalf("Report() failed: %v", err)
	}

	// Verify JSON is valid and well-formatted
	var doc Document
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("Invalid JSON output: %v", err)
	}

	// Verify indentation
	jsonStr := buf.String()
	if !bytes.Contains([]byte(jsonStr), []byte("\n  ")) {
		t.Error("JSON should be indented")
	}
}

func TestAggregatingReporter_MultiplePackages(t *testing.T) {
	t.Parallel()

	reporter := NewAggregatingReporter("/home/user/project")

	// Simulate findings from package 1
	fset1 := token.NewFileSet()
	fset1.AddFile("/home/user/project/pkg1/file1.go", 1, 100)
	findings1 := []detector.Finding{
		{
			Pos:     token.Pos(1),
			Message: "finding from pkg1",
			RuleID:  "sensitive-var",
		},
	}
	reporter.AddFindings(findings1, fset1)

	// Simulate findings from package 2
	fset2 := token.NewFileSet()
	fset2.AddFile("/home/user/project/pkg2/file2.go", 1, 100)
	findings2 := []detector.Finding{
		{
			Pos:     token.Pos(1),
			Message: "finding from pkg2",
			RuleID:  "sensitive-field",
		},
	}
	reporter.AddFindings(findings2, fset2)

	var buf bytes.Buffer
	if err := reporter.Report(&buf); err != nil {
		t.Fatalf("Report() failed: %v", err)
	}

	var doc Document
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("Failed to parse SARIF JSON: %v", err)
	}

	if len(doc.Runs[0].Results) != 2 {
		t.Errorf("results count = %d, want 2", len(doc.Runs[0].Results))
	}

	// Verify file paths
	wantURIs := []string{"pkg1/file1.go", "pkg2/file2.go"}
	gotURIs := []string{
		doc.Runs[0].Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI,
		doc.Runs[0].Results[1].Locations[0].PhysicalLocation.ArtifactLocation.URI,
	}
	if !reflect.DeepEqual(gotURIs, wantURIs) {
		t.Errorf("URIs = %v, want %v", gotURIs, wantURIs)
	}
}

func TestAggregatingReporter_Fingerprints(t *testing.T) {
	t.Parallel()

	reporter := NewAggregatingReporter("/home/user/project")
	fset := token.NewFileSet()
	fset.AddFile("/home/user/project/test.go", 1, 100)

	findings := []detector.Finding{
		{
			Pos:     token.Pos(1),
			Message: "test finding",
			RuleID:  "sensitive-var",
		},
	}

	reporter.AddFindings(findings, fset)

	var buf bytes.Buffer
	if err := reporter.Report(&buf); err != nil {
		t.Fatalf("Report() failed: %v", err)
	}

	var doc Document
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("Failed to parse SARIF JSON: %v", err)
	}

	result := doc.Runs[0].Results[0]
	if result.PartialFingerprints == nil {
		t.Fatal("PartialFingerprints should not be nil")
	}

	hash, ok := result.PartialFingerprints["primaryLocationLineHash"]
	if !ok {
		t.Error("primaryLocationLineHash should be present in fingerprints")
	}
	if hash == "" {
		t.Error("fingerprint hash should not be empty")
	}
	if len(hash) != 32 { // 16 bytes in hex = 32 characters
		t.Errorf("fingerprint hash length = %d, want 32", len(hash))
	}
}

func TestAggregatingReporter_RelativePaths(t *testing.T) {
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
			filePath: "/home/user/project/pkg/test.go",
			wantURI:  "pkg/test.go",
		},
		{
			name:     "file in root",
			workDir:  "/home/user/project",
			filePath: "/home/user/project/test.go",
			wantURI:  "test.go",
		},
		{
			name:     "file outside workDir",
			workDir:  "/home/user/project",
			filePath: "/other/path/test.go",
			wantURI:  "../../../other/path/test.go",
		},
	}

	for _, tt := range tests {
		tt := tt // capture range variable
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			reporter := NewAggregatingReporter(tt.workDir)
			fset := token.NewFileSet()
			fset.AddFile(tt.filePath, 1, 100)

			findings := []detector.Finding{
				{
					Pos:     token.Pos(1),
					Message: "test",
					RuleID:  "sensitive-var",
				},
			}

			reporter.AddFindings(findings, fset)

			var buf bytes.Buffer
			if err := reporter.Report(&buf); err != nil {
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
