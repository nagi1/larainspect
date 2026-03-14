package reportfmt

import (
	"strings"
	"testing"
	"time"

	"github.com/nagi1/larainspect/internal/model"
)

func TestDescribeTarget(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name   string
		target model.Target
		want   string
	}{
		{name: "path", target: model.Target{Path: "/tmp/demo"}, want: "/tmp/demo"},
		{name: "name and value", target: model.Target{Name: "service", Value: "nginx"}, want: "service=nginx"},
		{name: "name only", target: model.Target{Name: "nginx"}, want: "nginx"},
		{name: "value only", target: model.Target{Value: "demo"}, want: "demo"},
		{name: "type fallback", target: model.Target{Type: "listener"}, want: "listener"},
		{name: "unknown fallback", target: model.Target{}, want: "unknown"},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if got := DescribeTarget(testCase.target); got != testCase.want {
				t.Fatalf("DescribeTarget(%+v) = %q, want %q", testCase.target, got, testCase.want)
			}
		})
	}
}

func TestReportResultLabel(t *testing.T) {
	t.Parallel()

	cleanReport, err := model.BuildReport(model.Host{}, time.Unix(1700000000, 0), time.Second, nil, nil)
	if err != nil {
		t.Fatalf("BuildReport(clean) error = %v", err)
	}
	if got := ReportResultLabel(cleanReport); got != "clean" {
		t.Fatalf("ReportResultLabel(clean) = %q", got)
	}

	criticalReport, err := model.BuildReport(model.Host{}, time.Unix(1700000000, 0), time.Second, []model.Finding{sampleFinding(model.SeverityCritical, model.FindingClassDirect, "Critical finding")}, nil)
	if err != nil {
		t.Fatalf("BuildReport(critical) error = %v", err)
	}
	if got := ReportResultLabel(criticalReport); got != "critical risk" {
		t.Fatalf("ReportResultLabel(critical) = %q", got)
	}

	unknownOnlyReport, err := model.BuildReport(model.Host{}, time.Unix(1700000000, 0), time.Second, nil, []model.Unknown{{
		ID:      "unknown.only",
		CheckID: "unknown.only",
		Title:   "Unknown only",
		Reason:  "missing data",
		Error:   model.ErrorKindNotEnoughData,
	}})
	if err != nil {
		t.Fatalf("BuildReport(unknownOnly) error = %v", err)
	}
	if got := ReportResultLabel(unknownOnlyReport); got != "unknown-only" {
		t.Fatalf("ReportResultLabel(unknown-only) = %q", got)
	}
}

func TestDefaultStringAndClassLabels(t *testing.T) {
	t.Parallel()

	if got := DefaultString("   ", "fallback"); got != "fallback" {
		t.Fatalf("DefaultString() blank = %q", got)
	}
	if got := DefaultString("value", "fallback"); got != "value" {
		t.Fatalf("DefaultString() value = %q", got)
	}

	testCases := []struct {
		class           model.FindingClass
		wantLabel       string
		wantPriorityTag string
	}{
		{model.FindingClassDirect, "direct finding", "DIRECT"},
		{model.FindingClassHeuristic, "heuristic finding", "HEURISTIC"},
		{model.FindingClassCompromiseIndicator, "possible compromise indicator", "COMPROMISE"},
		{model.FindingClass("custom"), "custom", "CUSTOM"},
	}

	for _, testCase := range testCases {
		if got := FindingClassLabel(testCase.class); got != testCase.wantLabel {
			t.Fatalf("FindingClassLabel(%q) = %q", testCase.class, got)
		}
		if got := PriorityClassLabel(testCase.class); got != testCase.wantPriorityTag {
			t.Fatalf("PriorityClassLabel(%q) = %q", testCase.class, got)
		}
	}
}

func TestPriorityEntriesSortsAndCapsResults(t *testing.T) {
	t.Parallel()

	findings := []model.Finding{
		sampleFinding(model.SeverityHigh, model.FindingClassCompromiseIndicator, "Zulu"),
		sampleFinding(model.SeverityCritical, model.FindingClassDirect, "Alpha"),
		sampleFinding(model.SeverityMedium, model.FindingClassHeuristic, "Ignored"),
		sampleFinding(model.SeverityHigh, model.FindingClassDirect, "Beta"),
		sampleFinding(model.SeverityCritical, model.FindingClassDirect, "Gamma"),
		sampleFinding(model.SeverityHigh, model.FindingClassCompromiseIndicator, "Delta"),
	}
	unknowns := []model.Unknown{
		{ID: "unknown.1", CheckID: "unknown.1", Title: "Unknown one", Reason: "reason", Error: model.ErrorKindPermissionDenied},
		{ID: "unknown.2", CheckID: "unknown.2", Title: "Unknown two", Reason: "reason", Error: model.ErrorKindParseFailure},
	}

	report, err := model.BuildReport(model.Host{}, time.Unix(1700000000, 0), time.Second, findings, unknowns)
	if err != nil {
		t.Fatalf("BuildReport() error = %v", err)
	}

	entries := PriorityEntries(report)
	if len(entries) != 6 {
		t.Fatalf("expected priority list to be capped at 6, got %d", len(entries))
	}
	if entries[0].Severity != model.SeverityCritical || entries[0].Title != "Alpha" {
		t.Fatalf("unexpected first entry %+v", entries[0])
	}
	if entries[1].Severity != model.SeverityCritical || entries[1].Title != "Gamma" {
		t.Fatalf("unexpected second entry %+v", entries[1])
	}
}

func sampleFinding(severity model.Severity, class model.FindingClass, title string) model.Finding {
	return model.Finding{
		ID:          strings.ToLower(strings.ReplaceAll(title, " ", ".")),
		CheckID:     "demo.check",
		Class:       class,
		Severity:    severity,
		Confidence:  model.ConfidenceConfirmed,
		Title:       title,
		Why:         "why",
		Remediation: "fix",
		Evidence:    []model.Evidence{{Label: "demo", Detail: "value"}},
	}
}
