package terminal_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/nagi1/larainspect/internal/report/terminal"
	"github.com/nagi1/larainspect/internal/testfixtures"
)

func TestReporterMatchesGoldenFile(t *testing.T) {
	t.Parallel()

	report, err := testfixtures.SampleReport()
	if err != nil {
		t.Fatalf("SampleReport() error = %v", err)
	}

	var output bytes.Buffer
	if err := terminal.NewReporter().Render(&output, report); err != nil {
		t.Fatalf("Render() error = %v", err)
	}

	goldenPath := filepath.Join("testdata", "sample_report.golden.txt")
	golden, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("ReadFile(%q) error = %v", goldenPath, err)
	}

	if output.String() != string(golden) {
		t.Fatalf("golden mismatch\nexpected:\n%s\nactual:\n%s", string(golden), output.String())
	}
}
