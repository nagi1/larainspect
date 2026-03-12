package model_test

import (
	"testing"
	"time"

	"github.com/nagi1/larainspect/internal/model"
)

func TestBuildReportGroupsFindingsByClass(t *testing.T) {
	t.Parallel()

	findings := []model.Finding{
		{
			ID:          "filesystem.writable_code",
			CheckID:     "filesystem.writable_code",
			Class:       model.FindingClassDirect,
			Severity:    model.SeverityHigh,
			Confidence:  model.ConfidenceConfirmed,
			Title:       "Writable application code",
			Why:         "Writable code can lead to runtime code execution changes.",
			Remediation: "Make the code tree read-only to the runtime user.",
			Evidence:    []model.Evidence{{Label: "mode", Detail: "0775"}},
		},
		{
			ID:          "heuristic.debug_mode",
			CheckID:     "heuristic.debug_mode",
			Class:       model.FindingClassHeuristic,
			Severity:    model.SeverityMedium,
			Confidence:  model.ConfidencePossible,
			Title:       "Debug mode may be enabled",
			Why:         "Verbose errors can expose internals.",
			Remediation: "Verify production debug settings.",
			Evidence:    []model.Evidence{{Label: "env", Detail: "APP_DEBUG=true"}},
		},
	}

	unknowns := []model.Unknown{
		{
			ID:      "nginx.config_read",
			CheckID: "nginx.config_read",
			Title:   "Could not inspect Nginx config",
			Reason:  "Permission denied while reading /etc/nginx/nginx.conf.",
			Error:   model.ErrorKindPermissionDenied,
		},
	}

	report, err := model.BuildReport(model.Host{Hostname: "demo-vps"}, time.Unix(1700000000, 0), 1500*time.Millisecond, findings, unknowns)
	if err != nil {
		t.Fatalf("BuildReport() error = %v", err)
	}

	if report.Summary.TotalFindings != 2 {
		t.Fatalf("expected 2 findings, got %d", report.Summary.TotalFindings)
	}

	if report.Summary.DirectFindings != 1 || len(report.DirectFindings) != 1 {
		t.Fatalf("expected one direct finding, got summary=%d len=%d", report.Summary.DirectFindings, len(report.DirectFindings))
	}

	if report.Summary.HeuristicFindings != 1 || len(report.HeuristicFindings) != 1 {
		t.Fatalf("expected one heuristic finding, got summary=%d len=%d", report.Summary.HeuristicFindings, len(report.HeuristicFindings))
	}

	if report.Summary.Unknowns != 1 || len(report.Unknowns) != 1 {
		t.Fatalf("expected one unknown, got summary=%d len=%d", report.Summary.Unknowns, len(report.Unknowns))
	}
}

func TestBuildReportCountsCompromiseIndicatorsAndRejectsInvalidFinding(t *testing.T) {
	t.Parallel()

	report, err := model.BuildReport(model.Host{}, time.Unix(1700000000, 0), time.Second, []model.Finding{
		{
			ID:          "forensics.sample",
			CheckID:     "forensics.sample",
			Class:       model.FindingClassCompromiseIndicator,
			Severity:    model.SeverityHigh,
			Confidence:  model.ConfidenceProbable,
			Title:       "Unexpected PHP file",
			Why:         "Could indicate persistence.",
			Remediation: "Investigate and remove if unauthorized.",
			Evidence:    []model.Evidence{{Label: "path", Detail: "/tmp/shell.php"}},
		},
	}, nil)
	if err != nil {
		t.Fatalf("BuildReport() error = %v", err)
	}

	if report.Summary.CompromiseIndicators != 1 || len(report.CompromiseIndicators) != 1 {
		t.Fatalf("expected one compromise indicator, got %+v", report.Summary)
	}

	_, err = model.BuildReport(model.Host{}, time.Unix(1700000000, 0), time.Second, []model.Finding{{
		ID:       "bad",
		CheckID:  "bad",
		Class:    model.FindingClassDirect,
		Severity: model.SeverityHigh,
	}}, nil)
	if err == nil {
		t.Fatal("expected invalid finding error")
	}
}
