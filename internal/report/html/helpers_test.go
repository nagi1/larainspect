package html

import (
	"strings"
	"testing"

	"github.com/nagi1/larainspect/internal/model"
	"github.com/nagi1/larainspect/internal/report/reportfmt"
)

func TestSeveritySortingViaReportfmt(t *testing.T) {
	t.Parallel()

	findings := []model.Finding{
		{Severity: model.SeverityLow, Title: "low"},
		{Severity: model.SeverityCritical, Title: "critical"},
		{Severity: model.SeverityHigh, Title: "high"},
	}
	reportfmt.SortFindings(findings)
	if findings[0].Title != "critical" || findings[1].Title != "high" || findings[2].Title != "low" {
		t.Fatalf("unexpected severity ordering %+v", findings)
	}
}

func TestWriteUnknownCardRendersEvidenceAndAffectedTargets(t *testing.T) {
	t.Parallel()

	var builder strings.Builder
	writeUnknownCard(&builder, model.Unknown{
		ID:      "unknown.demo",
		CheckID: "demo.check",
		Title:   "Demo unknown",
		Reason:  "permission denied",
		Error:   model.ErrorKindPermissionDenied,
		Evidence: []model.Evidence{
			{Label: "path", Detail: "/etc/nginx/nginx.conf"},
		},
		Affected: []model.Target{
			{Type: "path", Path: "/etc/nginx/nginx.conf"},
		},
	}, 2)

	output := builder.String()
	for _, want := range []string{
		`id="unknown-2"`,
		"Demo unknown",
		"permission denied",
		"/etc/nginx/nginx.conf",
		"Evidence",
		"Affected",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("expected unknown card output to contain %q, got %q", want, output)
		}
	}
}
