package main

import (
	"golang.org/x/tools/go/analysis/singlechecker"

	"github.com/nilpoona/leakhound"
)

func main() {
	singlechecker.Main(leakhound.Analyzer)
}
