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

func TestReportFindingsAndRebuildReport(t *testing.T) {
	t.Parallel()

	findings := []model.Finding{
		{
			ID:          "direct.demo",
			CheckID:     "direct.demo",
			Class:       model.FindingClassDirect,
			Severity:    model.SeverityHigh,
			Confidence:  model.ConfidenceConfirmed,
			Title:       "Direct finding",
			Why:         "demo",
			Remediation: "fix demo",
			Evidence:    []model.Evidence{{Label: "demo", Detail: "one"}},
		},
		{
			ID:          "heuristic.demo",
			CheckID:     "heuristic.demo",
			Class:       model.FindingClassHeuristic,
			Severity:    model.SeverityLow,
			Confidence:  model.ConfidencePossible,
			Title:       "Heuristic finding",
			Why:         "demo",
			Remediation: "fix demo",
			Evidence:    []model.Evidence{{Label: "demo", Detail: "two"}},
		},
	}

	report, err := model.BuildReport(model.Host{Hostname: "demo-vps"}, time.Unix(1700000000, 0), 1500*time.Millisecond, findings, nil)
	if err != nil {
		t.Fatalf("BuildReport() error = %v", err)
	}

	flattenedFindings := report.Findings()
	if len(flattenedFindings) != 2 {
		t.Fatalf("expected 2 flattened findings, got %d", len(flattenedFindings))
	}

	rebuiltReport, err := model.RebuildReport(report, flattenedFindings[:1], report.Unknowns)
	if err != nil {
		t.Fatalf("RebuildReport() error = %v", err)
	}

	if rebuiltReport.GeneratedAt != report.GeneratedAt || rebuiltReport.Duration != report.Duration {
		t.Fatalf("expected rebuilt report metadata to match original, got %+v", rebuiltReport)
	}
	if rebuiltReport.Summary.TotalFindings != 1 || rebuiltReport.Summary.DirectFindings != 1 || rebuiltReport.Summary.HeuristicFindings != 0 {
		t.Fatalf("unexpected rebuilt summary %+v", rebuiltReport.Summary)
	}
}

func TestFindingFingerprintIsStableAcrossWordingChanges(t *testing.T) {
	t.Parallel()

	firstFinding := model.Finding{
		ID:          "demo.finding",
		CheckID:     "demo.check",
		Class:       model.FindingClassDirect,
		Severity:    model.SeverityHigh,
		Confidence:  model.ConfidenceConfirmed,
		Title:       "First title",
		Why:         "First why",
		Remediation: "First remediation",
		Evidence:    []model.Evidence{{Label: "demo", Detail: "value"}},
		Affected:    []model.Target{{Type: "path", Path: "/srv/www/.env"}},
	}
	secondFinding := firstFinding
	secondFinding.Title = "Second title"
	secondFinding.Why = "Second why"
	secondFinding.Remediation = "Second remediation"

	if firstFinding.Fingerprint() != secondFinding.Fingerprint() {
		t.Fatalf("expected wording-only changes to preserve fingerprint: %q vs %q", firstFinding.Fingerprint(), secondFinding.Fingerprint())
	}
}
