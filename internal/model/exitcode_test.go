package model_test

import (
	"testing"
	"time"

	"github.com/nagi1/larainspect/internal/model"
)

func TestExitCodeForReport(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		findings []model.Finding
		unknowns []model.Unknown
		want     model.ExitCode
	}{
		{
			name: "clean report",
			want: model.ExitCodeClean,
		},
		{
			name: "unknown only",
			unknowns: []model.Unknown{{
				ID:      "demo.unknown",
				CheckID: "demo",
				Title:   "Could not inspect target",
				Reason:  "permission denied",
				Error:   model.ErrorKindPermissionDenied,
			}},
			want: model.ExitCodeLowRisk,
		},
		{
			name:     "medium finding",
			findings: []model.Finding{sampleFinding(model.SeverityMedium)},
			want:     model.ExitCodeMediumRisk,
		},
		{
			name:     "critical finding",
			findings: []model.Finding{sampleFinding(model.SeverityCritical)},
			want:     model.ExitCodeCriticalRisk,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			report, err := model.BuildReport(model.Host{}, time.Unix(1700000000, 0), time.Second, testCase.findings, testCase.unknowns)
			if err != nil {
				t.Fatalf("BuildReport() error = %v", err)
			}

			if got := model.ExitCodeForReport(report); got != testCase.want {
				t.Fatalf("ExitCodeForReport() = %d, want %d", got, testCase.want)
			}
		})
	}
}

func TestBuildReportInitializesAllSeverityBuckets(t *testing.T) {
	t.Parallel()

	report, err := model.BuildReport(model.Host{}, time.Unix(1700000000, 0), time.Second, nil, nil)
	if err != nil {
		t.Fatalf("BuildReport() error = %v", err)
	}

	for _, severity := range []model.Severity{
		model.SeverityCritical,
		model.SeverityHigh,
		model.SeverityMedium,
		model.SeverityLow,
		model.SeverityInformational,
	} {
		if _, ok := report.Summary.SeverityCounts[severity]; !ok {
			t.Fatalf("missing severity bucket %q", severity)
		}
	}
}

func TestHighestSeverityOrClean(t *testing.T) {
	t.Parallel()

	cleanReport, err := model.BuildReport(model.Host{}, time.Unix(1700000000, 0), time.Second, nil, nil)
	if err != nil {
		t.Fatalf("BuildReport(clean) error = %v", err)
	}
	if got := cleanReport.HighestSeverityOrClean(); got != "clean" {
		t.Fatalf("HighestSeverityOrClean(clean) = %q", got)
	}

	unknownReport, err := model.BuildReport(model.Host{}, time.Unix(1700000000, 0), time.Second, nil, []model.Unknown{{
		ID:      "demo.unknown",
		CheckID: "demo",
		Title:   "Could not inspect target",
		Reason:  "permission denied",
		Error:   model.ErrorKindPermissionDenied,
	}})
	if err != nil {
		t.Fatalf("BuildReport(unknown) error = %v", err)
	}
	if got := unknownReport.HighestSeverityOrClean(); got != "unknown-only" {
		t.Fatalf("HighestSeverityOrClean(unknown) = %q", got)
	}
}

func sampleFinding(severity model.Severity) model.Finding {
	return model.Finding{
		ID:          "demo.finding",
		CheckID:     "demo.finding",
		Class:       model.FindingClassDirect,
		Severity:    severity,
		Confidence:  model.ConfidenceConfirmed,
		Title:       "Demo finding",
		Why:         "Demo why",
		Remediation: "Demo remediation",
		Evidence:    []model.Evidence{{Label: "demo", Detail: "evidence"}},
	}
}
