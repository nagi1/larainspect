package sarif_test

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/nagi1/larainspect/internal/model"
	"github.com/nagi1/larainspect/internal/report/sarif"
)

func testReport() model.Report {
	report, _ := model.BuildReport(
		model.Host{Hostname: "test-host", OS: "linux", Arch: "amd64"},
		time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		5*time.Second,
		[]model.Finding{
			{
				ID:          "direct-1",
				CheckID:     "APP_DEBUG_ENABLED",
				Class:       model.FindingClassDirect,
				Severity:    model.SeverityHigh,
				Confidence:  model.ConfidenceConfirmed,
				Title:       "APP_DEBUG is enabled in production",
				Why:         "Debug mode leaks stack traces and environment variables to end users.",
				Remediation: "Set APP_DEBUG=false in your .env file.",
				Evidence:    []model.Evidence{{Label: "env", Detail: "APP_DEBUG=true"}},
				Affected:    []model.Target{{Type: "file", Path: "/var/www/app/.env"}},
			},
			{
				ID:          "heuristic-1",
				CheckID:     "WEAK_SESSION_CONFIG",
				Class:       model.FindingClassHeuristic,
				Severity:    model.SeverityMedium,
				Confidence:  model.ConfidenceProbable,
				Title:       "Session cookies may lack Secure flag",
				Why:         "Without the Secure flag, session cookies can be sent over HTTP.",
				Remediation: "Set SESSION_SECURE_COOKIE=true in your .env.",
				Evidence:    []model.Evidence{{Label: "config", Detail: "secure_cookie=false"}},
				Affected:    []model.Target{{Type: "config", Path: "config/session.php"}},
			},
		},
		[]model.Unknown{
			{
				ID:       "unknown-1",
				CheckID:  "PHP_VERSION_CHECK",
				Title:    "Could not determine PHP version",
				Reason:   "php binary not found in PATH",
				Error:    model.ErrorKindCommandMissing,
				Evidence: []model.Evidence{{Label: "error", Detail: "exec: php: not found"}},
			},
		},
	)
	return report
}

func TestSARIFReporterFormat(t *testing.T) {
	r := sarif.NewReporter()
	if r.Format() != "sarif" {
		t.Fatalf("Format() = %q, want sarif", r.Format())
	}
}

func TestSARIFReporterRender(t *testing.T) {
	r := sarif.NewReporter()
	report := testReport()

	var buf bytes.Buffer
	if err := r.Render(&buf, report); err != nil {
		t.Fatalf("Render() error: %v", err)
	}

	// Parse the output to verify structure.
	var doc map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	// Verify SARIF version.
	if v, ok := doc["version"].(string); !ok || v != "2.1.0" {
		t.Errorf("version = %q, want 2.1.0", v)
	}

	// Verify schema.
	if _, ok := doc["$schema"].(string); !ok {
		t.Error("missing $schema field")
	}

	// Verify runs array has one entry.
	runs, ok := doc["runs"].([]interface{})
	if !ok || len(runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(runs))
	}

	run := runs[0].(map[string]interface{})

	// Verify tool name.
	tool := run["tool"].(map[string]interface{})
	driver := tool["driver"].(map[string]interface{})
	if name := driver["name"].(string); name != "Larainspect" {
		t.Errorf("tool.driver.name = %q, want Larainspect", name)
	}

	// Verify rules exist.
	rules, ok := driver["rules"].([]interface{})
	if !ok || len(rules) != 2 {
		t.Errorf("expected 2 rules, got %d", len(rules))
	}

	// Verify results (2 findings, unknowns excluded from SARIF results).
	results, ok := run["results"].([]interface{})
	if !ok || len(results) != 2 {
		t.Errorf("expected 2 results, got %d", len(results))
	}

	// Verify first result severity mapping.
	if len(results) > 0 {
		result0 := results[0].(map[string]interface{})
		if result0["level"] != "error" {
			t.Errorf("first result level = %q, want error (high severity)", result0["level"])
		}
	}

	// Verify second result severity mapping.
	if len(results) > 1 {
		result1 := results[1].(map[string]interface{})
		if result1["level"] != "warning" {
			t.Errorf("second result level = %q, want warning (medium severity)", result1["level"])
		}
	}
}

func TestSARIFFingerprints(t *testing.T) {
	r := sarif.NewReporter()
	report := testReport()

	var buf bytes.Buffer
	if err := r.Render(&buf, report); err != nil {
		t.Fatalf("Render() error: %v", err)
	}

	var doc struct {
		Runs []struct {
			Results []struct {
				PartialFingerprints map[string]string `json:"partialFingerprints"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	for i, result := range doc.Runs[0].Results {
		fp, ok := result.PartialFingerprints["larainspect/v1"]
		if !ok || fp == "" {
			t.Errorf("result[%d] missing larainspect/v1 fingerprint", i)
		}
	}
}

func TestSARIFEmptyReport(t *testing.T) {
	r := sarif.NewReporter()
	report, _ := model.BuildReport(
		model.Host{},
		time.Now(),
		0,
		nil,
		nil,
	)

	var buf bytes.Buffer
	if err := r.Render(&buf, report); err != nil {
		t.Fatalf("Render() error: %v", err)
	}

	var doc struct {
		Runs []struct {
			Results []interface{} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(doc.Runs[0].Results) != 0 {
		t.Errorf("expected 0 results for empty report, got %d", len(doc.Runs[0].Results))
	}
}
