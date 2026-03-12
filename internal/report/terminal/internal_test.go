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
}

func TestDescribeTargetAndDefaultString(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		target model.Target
		want   string
	}{
		{target: model.Target{Path: "/tmp/demo"}, want: "/tmp/demo"},
		{target: model.Target{Name: "service", Value: "nginx"}, want: "service=nginx"},
		{target: model.Target{Name: "nginx"}, want: "nginx"},
		{target: model.Target{Value: "demo"}, want: "demo"},
	}

	for _, testCase := range testCases {
		if got := describeTarget(testCase.target); got != testCase.want {
			t.Fatalf("describeTarget(%+v) = %q, want %q", testCase.target, got, testCase.want)
		}
	}

	if got := defaultString("", "fallback"); got != "fallback" {
		t.Fatalf("defaultString() = %q, want fallback", got)
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
