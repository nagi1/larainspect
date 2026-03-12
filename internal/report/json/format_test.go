package json_test

import (
	"testing"

	jsonreport "github.com/nagi/larainspect/internal/report/json"
)

func TestReporterFormat(t *testing.T) {
	t.Parallel()

	if got := jsonreport.NewReporter().Format(); got != "json" {
		t.Fatalf("Format() = %q, want json", got)
	}
}
