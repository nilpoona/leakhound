package leakhound_test

import (
	"testing"

	"github.com/nilpoona/leakhound"
	"golang.org/x/tools/go/analysis/analysistest"
)

func Test(t *testing.T) {
	testdata := analysistest.TestData()
	patterns := []string{
		"sensitive",
	}

	for _, pattern := range patterns {
		t.Run(pattern, func(t *testing.T) {
			t.Parallel()
			analysistest.Run(t, testdata, leakhound.Analyzer, pattern)
		})
	}
}
