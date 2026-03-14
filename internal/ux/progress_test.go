package ux

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/nagi1/larainspect/internal/model"
	"github.com/nagi1/larainspect/internal/progress"
)

func TestProgressPrinterModes(t *testing.T) {
	t.Parallel()

	var quiet bytes.Buffer
	quietPrinter := NewProgressPrinter(&quiet, model.AuditConfig{Verbosity: model.VerbosityQuiet})
	quietPrinter.Handle(progress.Event{Type: progress.EventStageStarted, Stage: progress.StageDiscovery})
	if quiet.Len() != 0 {
		t.Fatalf("expected quiet progress to be empty, got %q", quiet.String())
	}

	var normal bytes.Buffer
	normalPrinter := NewProgressPrinter(&normal, model.AuditConfig{Verbosity: model.VerbosityNormal})
	normalPrinter.Handle(progress.Event{
		Type:    progress.EventStageStarted,
		Stage:   progress.StageDiscovery,
		Message: "collecting host and Laravel evidence",
	})
	normalPrinter.Handle(progress.Event{
		Type:           progress.EventContextResolved,
		AppCount:       1,
		AppName:        "acme/shop",
		LaravelVersion: "v11.9.0",
		PHPVersion:     "^8.2",
		PackageCount:   3,
		SourceMatches:  2,
		ArtifactCount:  1,
	})
	normalPrinter.Handle(progress.Event{Type: progress.EventFindingDiscovered, Severity: model.SeverityHigh})
	normalPrinter.Handle(progress.Event{Type: progress.EventCheckCompleted, ComponentID: "checks.demo", Findings: 1, Unknowns: 0, Completed: 1, Total: 1})
	if !strings.Contains(normal.String(), "Audit progress") || !strings.Contains(normal.String(), "Stages: Setup -> Discovery -> Checks -> Correlation -> Post-Process -> Report") || !strings.Contains(normal.String(), "[2/6] Discovery") {
		t.Fatalf("unexpected normal progress output %q", normal.String())
	}
	for _, want := range []string{
		"context: apps=1 primary=acme/shop laravel=v11.9.0 php=^8.2 packages=3 source_matches=2 artifacts=1",
		"live totals: findings=1 unknowns=0 critical=0 high=1 medium=0 low=0 informational=0",
	} {
		if !strings.Contains(normal.String(), want) {
			t.Fatalf("expected normal progress output to contain %q, got %q", want, normal.String())
		}
	}

	var verbose bytes.Buffer
	verbosePrinter := NewProgressPrinter(&verbose, model.AuditConfig{Verbosity: model.VerbosityVerbose})
	verbosePrinter.Handle(progress.Event{Type: progress.EventStageStarted, Stage: progress.StageChecks, Message: "running registered checks"})
	verbosePrinter.Handle(progress.Event{Type: progress.EventContextResolved, AppCount: 1, AppPath: "/srv/www/shop", NginxSites: 1, PHPFPMPools: 1, Listeners: 2})
	verbosePrinter.Handle(progress.Event{Type: progress.EventCheckRegistered, ComponentID: "checks.demo", Message: "demo check", Total: 1})
	verbosePrinter.Handle(progress.Event{Type: progress.EventCheckStarted, ComponentID: "checks.demo", Completed: 0, Total: 1})
	verbosePrinter.Handle(progress.Event{Type: progress.EventFindingDiscovered, ComponentID: "checks.demo", Severity: model.SeverityHigh, Class: model.FindingClassDirect, Title: "Demo finding"})
	verbosePrinter.Handle(progress.Event{Type: progress.EventUnknownObserved, ComponentID: "checks.demo", ErrorKind: model.ErrorKindPermissionDenied, Title: "Demo unknown"})
	verbosePrinter.Handle(progress.Event{Type: progress.EventCheckCompleted, ComponentID: "checks.demo", Findings: 2, Unknowns: 1, Completed: 1, Total: 1})
	verbosePrinter.Handle(progress.Event{Type: progress.EventStageCompleted, Stage: progress.StageChecks, Message: "direct=2 heuristic=0 unknowns=1"})
	verbosePrinter.Handle(progress.Event{Type: progress.EventAuditFailed, Err: errors.New("boom")})

	for _, want := range []string{
		"[3/6] Checks: running registered checks",
		"context: apps=1 primary=/srv/www/shop nginx=1 php_fpm=1 listeners=2",
		"registered check checks.demo: demo check",
		"starting check checks.demo [0/1]",
		"finding [HIGH][DIRECT] Demo finding",
		"unknown [PERMISSION_DENIED] Demo unknown",
		"check checks.demo complete [1/1]: +2 findings, +1 unknowns",
		"live totals: findings=1 unknowns=1 critical=0 high=1 medium=0 low=0 informational=0",
		"complete: direct=2 heuristic=0 unknowns=1",
		"Audit failed before report rendering: boom",
	} {
		if !strings.Contains(verbose.String(), want) {
			t.Fatalf("expected verbose progress output to contain %q, got %q", want, verbose.String())
		}
	}
}

func TestProgressPrinterFailureAndFallbackBranches(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	printer := NewProgressPrinter(&output, model.AuditConfig{
		Verbosity:    model.VerbosityVerbose,
		ScreenReader: true,
	})

	printer.Handle(progress.Event{Type: progress.EventStageStarted, Stage: progress.Stage("custom"), Message: "custom stage"})
	printer.Handle(progress.Event{Type: progress.EventCheckFailed, ComponentID: "", Err: errors.New("check boom"), Completed: 1, Total: 2})
	printer.Handle(progress.Event{Type: progress.EventCorrelatorFailed, ComponentID: "cor.demo", Err: errors.New("correlator boom"), Completed: 1, Total: 1})
	printer.Handle(progress.Event{Type: progress.EventStageCompleted, Stage: progress.StageReport})
	printer.Handle(progress.Event{Type: progress.EventAuditFailed, Err: errors.New("failed")})

	for _, want := range []string{
		"[1/6] custom: custom stage",
		"check unknown failed: check boom [1/2]",
		"correlator cor.demo failed: correlator boom [1/1]",
		"Audit failed: failed",
	} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("expected output to contain %q, got %q", want, output.String())
		}
	}
}

func TestClassLabel(t *testing.T) {
	t.Parallel()

	tests := []struct {
		class model.FindingClass
		want  string
	}{
		{model.FindingClassDirect, "DIRECT"},
		{model.FindingClassHeuristic, "HEURISTIC"},
		{model.FindingClassCompromiseIndicator, "COMPROMISE"},
		{model.FindingClass("other"), "OTHER"},
	}
	for _, tt := range tests {
		if got := classLabel(tt.class); got != tt.want {
			t.Fatalf("classLabel(%q) = %q, want %q", tt.class, got, tt.want)
		}
	}
}

func TestMaxCount(t *testing.T) {
	t.Parallel()

	if got := maxCount(5, 10); got != 10 {
		t.Fatalf("maxCount(5, 10) = %d, want 10", got)
	}
	if got := maxCount(10, 5); got != 10 {
		t.Fatalf("maxCount(10, 5) = %d, want 10", got)
	}
	if got := maxCount(7, 7); got != 7 {
		t.Fatalf("maxCount(7, 7) = %d, want 7", got)
	}
}

func TestProgressPrinterVerboseFindingAndUnknownFallbacks(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	printer := NewProgressPrinter(&output, model.AuditConfig{Verbosity: model.VerbosityVerbose})

	// Finding with empty title
	printer.Handle(progress.Event{
		Type:     progress.EventFindingDiscovered,
		Severity: model.SeverityLow,
		Class:    model.FindingClassDirect,
		Title:    "",
	})
	// Unknown with empty title
	printer.Handle(progress.Event{
		Type:      progress.EventUnknownObserved,
		ErrorKind: model.ErrorKindCommandTimeout,
		Title:     "",
	})
	// Correlator events for coverage
	printer.Handle(progress.Event{
		Type:        progress.EventCorrelatorRegistered,
		ComponentID: "cor.test",
		Message:     "test correlator",
	})
	printer.Handle(progress.Event{
		Type:        progress.EventCorrelatorStarted,
		ComponentID: "cor.test",
		Completed:   0,
		Total:       1,
	})
	printer.Handle(progress.Event{
		Type:        progress.EventCorrelatorCompleted,
		ComponentID: "cor.test",
		Findings:    0,
		Unknowns:    0,
		Completed:   1,
		Total:       1,
	})

	result := output.String()
	if !strings.Contains(result, "untitled finding") {
		t.Fatalf("expected 'untitled finding' fallback, got %q", result)
	}
	if !strings.Contains(result, "untitled unknown") {
		t.Fatalf("expected 'untitled unknown' fallback, got %q", result)
	}
	if !strings.Contains(result, "registered correlator cor.test: test correlator") {
		t.Fatalf("expected correlator registration, got %q", result)
	}
	if !strings.Contains(result, "starting correlator cor.test [0/1]") {
		t.Fatalf("expected correlator start, got %q", result)
	}
}

func TestProgressPrinterNilWriter(t *testing.T) {
	t.Parallel()

	printer := ProgressPrinter{}
	// Should not panic with nil writer
	printer.Handle(progress.Event{Type: progress.EventStageStarted, Stage: progress.StageDiscovery})
}

func TestProgressPrinterNormalOmitsVerboseDetails(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	printer := NewProgressPrinter(&output, model.AuditConfig{Verbosity: model.VerbosityNormal})

	printer.Handle(progress.Event{
		Type:        progress.EventCheckRegistered,
		ComponentID: "checks.hidden",
		Message:     "should not appear",
	})
	printer.Handle(progress.Event{
		Type:     progress.EventFindingDiscovered,
		Severity: model.SeverityLow,
		Title:    "should not appear finding",
	})

	result := output.String()
	if strings.Contains(result, "should not appear") {
		t.Fatalf("normal mode should omit verbose details, got %q", result)
	}
}

func TestProgressPrinterComponentProgressWithState(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	printer := NewProgressPrinter(&output, model.AuditConfig{Verbosity: model.VerbosityVerbose})

	// Register and complete a correlator to populate state
	printer.Handle(progress.Event{Type: progress.EventCorrelatorRegistered, ComponentID: "cor.a", Total: 2})
	printer.Handle(progress.Event{
		Type:        progress.EventCorrelatorStarted,
		ComponentID: "cor.a",
		Completed:   0,
		Total:       2,
	})

	result := output.String()
	if !strings.Contains(result, "starting correlator cor.a") {
		t.Fatalf("expected correlator start line, got %q", result)
	}
}

func TestProgressPrinterWriteFailureNilErr(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	printer := NewProgressPrinter(&output, model.AuditConfig{Verbosity: model.VerbosityNormal})

	printer.Handle(progress.Event{Type: progress.EventAuditFailed})

	if strings.Contains(output.String(), "Audit failed") {
		t.Fatal("nil error should suppress failure message")
	}
}

func TestProgressPrinterWriteComponentFailureNoErr(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	printer := NewProgressPrinter(&output, model.AuditConfig{Verbosity: model.VerbosityVerbose})

	printer.Handle(progress.Event{
		Type:        progress.EventCheckFailed,
		ComponentID: "check.no_err",
		Completed:   0,
		Total:       1,
	})

	result := output.String()
	if !strings.Contains(result, "check check.no_err failed") {
		t.Fatalf("expected failure line without error detail, got %q", result)
	}
}

func TestProgressPrinterWriteStageCompletionWithMessage(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	printer := NewProgressPrinter(&output, model.AuditConfig{Verbosity: model.VerbosityVerbose})

	printer.Handle(progress.Event{
		Type:    progress.EventStageCompleted,
		Stage:   progress.StageChecks,
		Message: "direct=5 heuristic=3 unknowns=2",
	})

	if !strings.Contains(output.String(), "complete: direct=5 heuristic=3 unknowns=2") {
		t.Fatalf("expected completion message, got %q", output.String())
	}
}

func TestProgressPrinterWriteLiveTotalsZero(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	printer := NewProgressPrinter(&output, model.AuditConfig{Verbosity: model.VerbosityVerbose})

	// Trigger a stage start which calls writeLiveTotals, but with zero findings
	printer.Handle(progress.Event{
		Type:        progress.EventCheckCompleted,
		ComponentID: "checks.clean",
		Findings:    0,
		Unknowns:    0,
		Completed:   1,
		Total:       1,
	})

	if strings.Contains(output.String(), "live totals") {
		t.Fatalf("should skip live totals when all zero, got %q", output.String())
	}
}
