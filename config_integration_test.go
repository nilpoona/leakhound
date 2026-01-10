package leakhound_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nilpoona/leakhound"
	"golang.org/x/tools/go/analysis/analysistest"
)

func TestWithConfig(t *testing.T) {
	testdata := analysistest.TestData()
	customLoggerPath := filepath.Join(testdata, "src", "customlogger")

	// Save current directory
	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(originalDir)

	// Change to the test package directory so the analyzer finds .leakhound.yaml
	if err := os.Chdir(customLoggerPath); err != nil {
		t.Fatal(err)
	}

	// Run the analyzer - it should detect custom logger calls
	analysistest.Run(t, testdata, leakhound.Analyzer, "customlogger")
}
