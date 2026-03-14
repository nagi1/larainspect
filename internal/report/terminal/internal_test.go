package terminal

import (
	"bytes"
	"strings"
	"testing"

	"github.com/nagi1/larainspect/internal/model"
)

func TestReporterFormat(t *testing.T) {
	t.Parallel()

	if got := NewReporter().Format(); got != "terminal" {
		t.Fatalf("Format() = %q, want terminal", got)
	}
}

func TestRenderHandlesEmptyHostAndSections(t *testing.T) {
	t.Parallel()

	report := model.Report{
		SchemaVersion: model.SchemaVersion,
		Summary: model.Summary{
			SeverityCounts: map[model.Severity]int{
				model.SeverityCritical:      0,
				model.SeverityHigh:          0,
				model.SeverityMedium:        0,
				model.SeverityLow:           0,
				model.SeverityInformational: 0,
			},
		},
	}

	var output bytes.Buffer
	if err := NewReporter().Render(&output, report); err != nil {
		t.Fatalf("Render() error = %v", err)
	}

	if !strings.Contains(output.String(), "Host: unknown") {
		t.Fatalf("expected fallback host, got %q", output.String())
	}
	if !strings.Contains(output.String(), "Result: clean (exit code 0)") {
		t.Fatalf("expected clean result summary, got %q", output.String())
	}
}

func TestRenderUnknownSectionWithEvidence(t *testing.T) {
	t.Parallel()

	report := model.Report{
		SchemaVersion: model.SchemaVersion,
		Summary: model.Summary{
			Unknowns: 1,
			SeverityCounts: map[model.Severity]int{
				model.SeverityCritical:      0,
				model.SeverityHigh:          0,
				model.SeverityMedium:        0,
				model.SeverityLow:           0,
				model.SeverityInformational: 0,
			},
		},
		Unknowns: []model.Unknown{{
			ID:      "id",
			CheckID: "check",
			Title:   "title",
			Reason:  "reason",
			Error:   model.ErrorKindParseFailure,
			Evidence: []model.Evidence{
				{Label: "line", Detail: "broken"},
			},
		}},
	}

	var output bytes.Buffer
	if err := NewReporter().Render(&output, report); err != nil {
		t.Fatalf("Render() error = %v", err)
	}

	if !strings.Contains(output.String(), "Evidence:") {
		t.Fatalf("expected unknown evidence section, got %q", output.String())
	}
}

func TestRenderPriorityQueueIncludesCompromiseAndUnknowns(t *testing.T) {
	t.Parallel()

	report, err := model.BuildReport(
		model.Host{},
		model.Report{}.GeneratedAt,
		0,
		[]model.Finding{
			{
				ID:          "critical.direct",
				CheckID:     "critical.direct",
				Class:       model.FindingClassDirect,
				Severity:    model.SeverityCritical,
				Confidence:  model.ConfidenceConfirmed,
				Title:       "Critical direct finding",
				Why:         "why",
				Remediation: "fix",
				Evidence:    []model.Evidence{{Label: "demo", Detail: "value"}},
			},
			{
				ID:          "high.compromise",
				CheckID:     "high.compromise",
				Class:       model.FindingClassCompromiseIndicator,
				Severity:    model.SeverityHigh,
				Confidence:  model.ConfidenceProbable,
				Title:       "High compromise indicator",
				Why:         "why",
				Remediation: "fix",
				Evidence:    []model.Evidence{{Label: "demo", Detail: "value"}},
			},
		},
		[]model.Unknown{{
			ID:      "unknown.demo",
			CheckID: "unknown.demo",
			Title:   "Unknown evidence",
			Reason:  "reason",
			Error:   model.ErrorKindPermissionDenied,
		}},
	)
	if err != nil {
		t.Fatalf("BuildReport() error = %v", err)
	}

	var output bytes.Buffer
	if err := NewReporter().Render(&output, report); err != nil {
		t.Fatalf("Render() error = %v", err)
	}

	for _, want := range []string{
		"[CRITICAL][DIRECT] Critical direct finding",
		"[HIGH][COMPROMISE] High compromise indicator",
		"[UNKNOWN][PERMISSION_DENIED] Unknown evidence",
	} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("expected priority queue entry %q, got %q", want, output.String())
		}
	}
}
