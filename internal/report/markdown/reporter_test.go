package markdown_test

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/nagi1/larainspect/internal/model"
	markdownreport "github.com/nagi1/larainspect/internal/report/markdown"
	"github.com/nagi1/larainspect/internal/testfixtures"
)

func TestReporterFormat(t *testing.T) {
	t.Parallel()

	if got := markdownreport.NewReporter().Format(); got != "markdown" {
		t.Fatalf("Format() = %q, want %q", got, "markdown")
	}
}

func TestReporterRendersSummaryAndSections(t *testing.T) {
	t.Parallel()

	report, err := testfixtures.SampleReport()
	if err != nil {
		t.Fatalf("SampleReport() error = %v", err)
	}

	var output bytes.Buffer
	if err := markdownreport.NewReporter().Render(&output, report); err != nil {
		t.Fatalf("Render() error = %v", err)
	}

	for _, want := range []string{
		"# Larainspect Audit Report",
		"## Audit Summary",
		"## Priority Queue",
		"## Direct Findings (1)",
		"## Unknowns (1)",
		"filesystem.permissions",
	} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("expected markdown output to contain %q, got %q", want, output.String())
		}
	}
}

func TestReporterRendersPriorityQueueWithCriticalAndHigh(t *testing.T) {
	t.Parallel()

	report, err := testfixtures.SampleReport()
	if err != nil {
		t.Fatalf("SampleReport() error = %v", err)
	}

	var output bytes.Buffer
	if err := markdownreport.NewReporter().Render(&output, report); err != nil {
		t.Fatalf("Render() error = %v", err)
	}

	markdown := output.String()
	for _, want := range []string{
		"`CRITICAL`",
		"`HIGH`",
		"`UNKNOWN`",
		".env is writable by the web runtime",
		"Unexpected PHP file in public uploads path",
		"Could not inspect the main Nginx config",
	} {
		if !strings.Contains(markdown, want) {
			t.Fatalf("priority queue should contain %q", want)
		}
	}
}

func TestReporterRendersEvidenceAndAffected(t *testing.T) {
	t.Parallel()

	report, err := testfixtures.SampleReport()
	if err != nil {
		t.Fatalf("SampleReport() error = %v", err)
	}

	var output bytes.Buffer
	if err := markdownreport.NewReporter().Render(&output, report); err != nil {
		t.Fatalf("Render() error = %v", err)
	}

	markdown := output.String()
	for _, want := range []string{
		"- Evidence:",
		"**path:** /var/www/shop/.env",
		"**mode:** 0664",
		"- Affected:",
		"`/var/www/shop/.env`",
		"- Controls:",
		"`laravel.env-integrity-and-permissions` `implemented`",
	} {
		if !strings.Contains(markdown, want) {
			t.Fatalf("expected evidence/affected to contain %q", want)
		}
	}
}

func TestReporterRendersUnknownsWithAffectedAndEvidence(t *testing.T) {
	t.Parallel()

	unknowns := []model.Unknown{
		{
			ID:      "test.unknown",
			CheckID: "test.unknown",
			Title:   "Test unknown",
			Reason:  "Some reason.",
			Error:   model.ErrorKindCommandFailed,
			Affected: []model.Target{
				{Type: "path", Path: "/etc/test.conf"},
			},
			Evidence: []model.Evidence{
				{Label: "stderr", Detail: "permission denied"},
			},
		},
	}

	report, err := model.BuildReport(
		model.Host{Hostname: "test"},
		time.Now(),
		time.Second,
		nil,
		unknowns,
	)
	if err != nil {
		t.Fatalf("BuildReport() error = %v", err)
	}

	var output bytes.Buffer
	if err := markdownreport.NewReporter().Render(&output, report); err != nil {
		t.Fatalf("Render() error = %v", err)
	}

	markdown := output.String()
	for _, want := range []string{
		"## Unknowns (1)",
		"### Test unknown",
		"`/etc/test.conf`",
		"**stderr:** permission denied",
	} {
		if !strings.Contains(markdown, want) {
			t.Fatalf("unknowns markdown should contain %q", want)
		}
	}
}

func TestReporterRendersEmptyReport(t *testing.T) {
	t.Parallel()

	report, err := model.BuildReport(
		model.Host{Hostname: "clean-host"},
		time.Now(),
		500*time.Millisecond,
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("BuildReport() error = %v", err)
	}

	var output bytes.Buffer
	if err := markdownreport.NewReporter().Render(&output, report); err != nil {
		t.Fatalf("Render() error = %v", err)
	}

	markdown := output.String()
	if !strings.Contains(markdown, "No critical, high, or unknown items were promoted into the priority queue.") {
		t.Fatal("empty priority queue message missing")
	}
	if !strings.Contains(markdown, "## Direct Findings (0)") {
		t.Fatal("expected empty direct findings section")
	}
}

func TestReporterRendersHeuristicAndCompromiseFindings(t *testing.T) {
	t.Parallel()

	report, err := testfixtures.SampleReport()
	if err != nil {
		t.Fatalf("SampleReport() error = %v", err)
	}

	var output bytes.Buffer
	if err := markdownreport.NewReporter().Render(&output, report); err != nil {
		t.Fatalf("Render() error = %v", err)
	}

	markdown := output.String()
	for _, want := range []string{
		"## Heuristic Findings (1)",
		"APP_DEBUG appears to be enabled",
		"## Possible Compromise Indicators (1)",
		"Unexpected PHP file in public uploads path",
	} {
		if !strings.Contains(markdown, want) {
			t.Fatalf("expected markdown to contain %q", want)
		}
	}
}
