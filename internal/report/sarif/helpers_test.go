package sarif

import (
	"testing"

	"github.com/nagi1/larainspect/internal/model"
)

func TestLocationFromFinding(t *testing.T) {
	t.Parallel()

	if got := locationFromFinding(model.Finding{}); got != nil {
		t.Fatalf("expected nil location for finding without affected targets, got %+v", got)
	}

	location := locationFromFinding(model.Finding{
		Affected: []model.Target{
			{Type: "service", Name: "nginx"},
		},
	})
	if location == nil || location.PhysicalLocation.ArtifactLocation.URI != "nginx" {
		t.Fatalf("expected name fallback location, got %+v", location)
	}
}

func TestSeverityToSARIFSecurity(t *testing.T) {
	t.Parallel()

	testCases := map[model.Severity]string{
		model.SeverityCritical:      "critical",
		model.SeverityHigh:          "high",
		model.SeverityMedium:        "medium",
		model.SeverityLow:           "low",
		model.SeverityInformational: "informational",
		model.Severity("custom"):    "informational",
	}

	for severity, want := range testCases {
		if got := severityToSARIFSecurity(severity); got != want {
			t.Fatalf("severityToSARIFSecurity(%q) = %q, want %q", severity, got, want)
		}
	}
}
