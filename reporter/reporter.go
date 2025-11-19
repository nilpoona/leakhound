package reporter

import (
	"fmt"
	"os"

	"github.com/nilpoona/leakhound/detector"
	"github.com/nilpoona/leakhound/reporter/sarif"
	"github.com/nilpoona/leakhound/reporter/text"
	"golang.org/x/tools/go/analysis"
)

// Format specifies the output format
type Format string

const (
	FormatText  Format = "text"
	FormatSARIF Format = "sarif"
)

// Reporter is the interface that all reporters must implement
type Reporter interface {
	Report(findings []detector.Finding) error
}

// Config configures the reporter
type Config struct {
	Format  Format
	WorkDir string // For SARIF: base directory for relative paths
}

// New creates a reporter based on the given configuration
func New(pass *analysis.Pass, config Config) (Reporter, error) {
	switch config.Format {
	case FormatText, "":
		return text.NewReporter(pass), nil
	case FormatSARIF:
		if config.WorkDir == "" {
			wd, err := os.Getwd()
			if err != nil {
				return nil, fmt.Errorf("failed to get working directory: %w", err)
			}
			config.WorkDir = wd
		}
		return sarif.NewReporter(pass, os.Stdout, config.WorkDir), nil
	default:
		return nil, fmt.Errorf("unsupported format: %s", config.Format)
	}
}
