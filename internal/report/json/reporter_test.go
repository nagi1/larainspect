package json_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	jsonreport "github.com/nagi/larainspect/internal/report/json"
	"github.com/nagi/larainspect/internal/testfixtures"
)

func TestReporterMatchesGoldenFile(t *testing.T) {
	t.Parallel()

	report, err := testfixtures.SampleReport()
	if err != nil {
		t.Fatalf("SampleReport() error = %v", err)
	}

	var output bytes.Buffer
	if err := jsonreport.NewReporter().Render(&output, report); err != nil {
		t.Fatalf("Render() error = %v", err)
	}

	goldenPath := filepath.Join("testdata", "sample_report.golden.json")
	golden, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("ReadFile(%q) error = %v", goldenPath, err)
	}

	if output.String() != string(golden) {
		t.Fatalf("golden mismatch\nexpected:\n%s\nactual:\n%s", string(golden), output.String())
	}
}
