package tui

import (
	"errors"
	"testing"
	"time"

	"github.com/nagi1/larainspect/internal/model"
	"github.com/nagi1/larainspect/internal/progress"
)

func TestHandleBusEventAuditStarted(t *testing.T) {
	app := newTestApp()

	app.handleBusEvent(progress.Event{Type: progress.EventAuditStarted, At: time.Now()})

	if !app.auditRunning {
		t.Error("auditRunning should be true after EventAuditStarted")
	}
	snap := app.state.Snapshot()
	if len(snap.RecentEvents) != 1 {
		t.Errorf("recentEvents length = %d, want 1", len(snap.RecentEvents))
	}
}

func TestHandleBusEventContextResolved(t *testing.T) {
	app := newTestApp()
	app.handleBusEvent(progress.Event{
		Type:           progress.EventContextResolved,
		At:             time.Now(),
		AppName:        "myapp",
		AppPath:        "/srv/myapp",
		LaravelVersion: "10.2.1",
		PHPVersion:     "8.2.0",
		PackageCount:   42,
	})

	snap := app.state.Snapshot()
	if snap.Context.AppName != "myapp" {
		t.Errorf("AppName = %q, want %q", snap.Context.AppName, "myapp")
	}
	if snap.Context.AppPath != "/srv/myapp" {
		t.Errorf("AppPath = %q, want %q", snap.Context.AppPath, "/srv/myapp")
	}
	if snap.Context.LaravelVersion != "10.2.1" {
		t.Errorf("LaravelVersion = %q, want %q", snap.Context.LaravelVersion, "10.2.1")
	}
	if snap.Context.PHPVersion != "8.2.0" {
		t.Errorf("PHPVersion = %q, want %q", snap.Context.PHPVersion, "8.2.0")
	}
	if snap.Context.PackageCount != 42 {
		t.Errorf("PackageCount = %d, want 42", snap.Context.PackageCount)
	}
}

func TestHandleBusEventContextResolvedReplacesContext(t *testing.T) {
	app := newTestApp()

	app.handleBusEvent(progress.Event{
		Type:    progress.EventContextResolved,
		At:      time.Now(),
		AppName: "first-app",
		AppPath: "/srv/first",
	})
	app.handleBusEvent(progress.Event{
		Type:    progress.EventContextResolved,
		At:      time.Now(),
		AppName: "",
		AppPath: "/new/path",
	})

	snap := app.state.Snapshot()
	if snap.Context.AppPath != "/new/path" {
		t.Errorf("AppPath = %q, want %q", snap.Context.AppPath, "/new/path")
	}
}

func TestHandleBusEventStageStarted(t *testing.T) {
	app := newTestApp()
	app.handleBusEvent(progress.Event{
		Type:  progress.EventStageStarted,
		At:    time.Now(),
		Stage: progress.StageChecks,
	})

	snap := app.state.Snapshot()
	if snap.CurrentStage != progress.StageChecks {
		t.Errorf("currentStage = %q, want %q", snap.CurrentStage, progress.StageChecks)
	}
}

func TestRegisterComponent(t *testing.T) {
	app := newTestApp()

	app.handleBusEvent(progress.Event{
		Type:        progress.EventCheckRegistered,
		At:          time.Now(),
		ComponentID: "check-a",
	})
	app.handleBusEvent(progress.Event{
		Type:        progress.EventCorrelatorRegistered,
		At:          time.Now(),
		ComponentID: "corr-b",
	})

	snap := app.state.Snapshot()
	if len(snap.Checks) != 1 {
		t.Fatalf("checks length = %d, want 1", len(snap.Checks))
	}
	if len(snap.Correlators) != 1 {
		t.Fatalf("correlators length = %d, want 1", len(snap.Correlators))
	}
	if snap.Checks[0].Kind != progress.ComponentKindCheck {
		t.Errorf("checks[0].Kind = %q, want %q", snap.Checks[0].Kind, progress.ComponentKindCheck)
	}
	if snap.Checks[0].ID != "check-a" {
		t.Errorf("checks[0].ID = %q, want %q", snap.Checks[0].ID, "check-a")
	}
	if snap.Checks[0].Status != progress.ComponentStatusPending {
		t.Errorf("checks[0].Status = %q, want %q", snap.Checks[0].Status, progress.ComponentStatusPending)
	}
	if snap.Correlators[0].Kind != progress.ComponentKindCorrelator {
		t.Errorf("correlators[0].Kind = %q, want %q", snap.Correlators[0].Kind, progress.ComponentKindCorrelator)
	}
}

func TestComponentStatusTransitions(t *testing.T) {
	app := newTestApp()

	app.handleBusEvent(progress.Event{Type: progress.EventCheckRegistered, At: time.Now(), ComponentID: "check-a"})
	app.handleBusEvent(progress.Event{Type: progress.EventCheckRegistered, At: time.Now(), ComponentID: "check-b"})
	app.handleBusEvent(progress.Event{Type: progress.EventCheckStarted, At: time.Now(), ComponentID: "check-a"})

	snap := app.state.Snapshot()
	if snap.Checks[0].Status != progress.ComponentStatusRunning {
		t.Errorf("check-a status = %q, want running", snap.Checks[0].Status)
	}

	app.handleBusEvent(progress.Event{Type: progress.EventCheckCompleted, At: time.Now(), ComponentID: "check-a", Findings: 3, Unknowns: 1})
	snap = app.state.Snapshot()
	if snap.Checks[0].Status != progress.ComponentStatusCompleted {
		t.Errorf("check-a status = %q, want completed", snap.Checks[0].Status)
	}
	if snap.Checks[0].Findings != 3 {
		t.Errorf("check-a findings = %d, want 3", snap.Checks[0].Findings)
	}
	if snap.Checks[0].Unknowns != 1 {
		t.Errorf("check-a unknowns = %d, want 1", snap.Checks[0].Unknowns)
	}

	app.handleBusEvent(progress.Event{Type: progress.EventCheckFailed, At: time.Now(), ComponentID: "check-b"})
	snap = app.state.Snapshot()
	if snap.Checks[1].Status != progress.ComponentStatusFailed {
		t.Errorf("check-b status = %q, want failed", snap.Checks[1].Status)
	}
}

func TestCorrelatorStatusTransitions(t *testing.T) {
	app := newTestApp()

	app.handleBusEvent(progress.Event{Type: progress.EventCorrelatorRegistered, At: time.Now(), ComponentID: "corr-a"})
	app.handleBusEvent(progress.Event{Type: progress.EventCorrelatorStarted, At: time.Now(), ComponentID: "corr-a"})

	snap := app.state.Snapshot()
	if snap.Correlators[0].Status != progress.ComponentStatusRunning {
		t.Errorf("corr-a status = %q, want running", snap.Correlators[0].Status)
	}

	app.handleBusEvent(progress.Event{Type: progress.EventCorrelatorCompleted, At: time.Now(), ComponentID: "corr-a", Findings: 2})
	snap = app.state.Snapshot()
	if snap.Correlators[0].Status != progress.ComponentStatusCompleted {
		t.Errorf("corr-a status = %q, want completed", snap.Correlators[0].Status)
	}
	if snap.Correlators[0].Findings != 2 {
		t.Errorf("corr-a findings = %d, want 2", snap.Correlators[0].Findings)
	}
}

func TestCorrelatorFailed(t *testing.T) {
	app := newTestApp()
	app.handleBusEvent(progress.Event{Type: progress.EventCorrelatorRegistered, At: time.Now(), ComponentID: "corr-a"})
	app.handleBusEvent(progress.Event{Type: progress.EventCorrelatorFailed, At: time.Now(), ComponentID: "corr-a"})

	snap := app.state.Snapshot()
	if snap.Correlators[0].Status != progress.ComponentStatusFailed {
		t.Errorf("corr-a status = %q, want failed", snap.Correlators[0].Status)
	}
}

func TestFindingDiscoveredUpdatesCounts(t *testing.T) {
	app := newTestApp()

	app.handleBusEvent(progress.Event{Type: progress.EventFindingDiscovered, At: time.Now(), Severity: model.SeverityCritical})
	app.handleBusEvent(progress.Event{Type: progress.EventFindingDiscovered, At: time.Now(), Severity: model.SeverityCritical})
	app.handleBusEvent(progress.Event{Type: progress.EventFindingDiscovered, At: time.Now(), Severity: model.SeverityHigh})

	snap := app.state.Snapshot()
	if snap.SeverityCounts[model.SeverityCritical] != 2 {
		t.Errorf("critical count = %d, want 2", snap.SeverityCounts[model.SeverityCritical])
	}
	if snap.SeverityCounts[model.SeverityHigh] != 1 {
		t.Errorf("high count = %d, want 1", snap.SeverityCounts[model.SeverityHigh])
	}
}

func TestAuditCompletedWithoutReport(t *testing.T) {
	app := newTestApp()
	app.auditRunning = true

	cmd := app.handleBusEvent(progress.Event{Type: progress.EventAuditCompleted, At: time.Now()})

	if app.auditRunning {
		t.Error("auditRunning should be false after completed")
	}
	if !app.auditComplete {
		t.Error("auditComplete should be true")
	}
	if cmd != nil {
		t.Error("without report, no view switch command should be returned")
	}
}

func TestAuditCompletedWithReportSwitchesView(t *testing.T) {
	app := newTestApp()
	app.auditRunning = true

	app.handleBusEvent(progress.Event{
		Type:    progress.EventContextResolved,
		At:      time.Now(),
		AppName: "testapp",
		AppPath: "/tmp/testapp",
	})
	app.SetReport(model.Report{
		SchemaVersion: model.SchemaVersion,
		Duration:      "1.5s",
		Summary:       model.Summary{TotalFindings: 5},
	})

	cmd := app.handleBusEvent(progress.Event{Type: progress.EventAuditCompleted, At: time.Now()})

	if !app.auditComplete {
		t.Error("auditComplete should be true")
	}
	if app.resultsView == nil {
		t.Error("resultsView should be initialized")
	}
	if cmd == nil {
		t.Fatal("should return view switch command")
	}

	msg := cmd()
	if switchMsg, ok := msg.(switchViewMsg); !ok || switchMsg.view != ViewResults {
		t.Error("command should switch to ViewResults")
	}
}

func TestAuditCompletedAutoSwitchesToResults(t *testing.T) {
	app := newTestApp()
	app.auditRunning = true
	app.activeView = ViewScan

	app.handleBusEvent(progress.Event{
		Type:    progress.EventContextResolved,
		At:      time.Now(),
		AppName: "testapp",
	})
	app.SetReport(model.Report{
		SchemaVersion: model.SchemaVersion,
		Duration:      "2s",
		Summary:       model.Summary{TotalFindings: 3},
	})

	cmd := app.handleBusEvent(progress.Event{Type: progress.EventAuditCompleted, At: time.Now()})
	if cmd == nil {
		t.Fatal("audit completed with report should return switch command")
	}

	app.Update(cmd())
	if app.activeView != ViewResults {
		t.Errorf("activeView = %d, want ViewResults after auto-switch", app.activeView)
	}
}

func TestAuditCompletedWithoutReportStaysOnScan(t *testing.T) {
	app := newTestApp()
	app.auditRunning = true
	app.activeView = ViewScan

	cmd := app.handleBusEvent(progress.Event{Type: progress.EventAuditCompleted, At: time.Now()})
	if cmd != nil {
		t.Error("audit completed without report should not return switch command")
	}
	if app.activeView != ViewScan {
		t.Errorf("activeView = %d, want ViewScan when no report", app.activeView)
	}
}

func TestReportReadyAfterAuditCompletedSwitchesToResults(t *testing.T) {
	app := newTestApp()
	app.auditRunning = true
	app.activeView = ViewScan

	app.handleBusEvent(progress.Event{
		Type:    progress.EventContextResolved,
		At:      time.Now(),
		AppName: "testapp",
		AppPath: "/tmp/testapp",
	})

	cmd := app.handleBusEvent(progress.Event{Type: progress.EventAuditCompleted, At: time.Now()})
	if cmd != nil {
		t.Fatal("audit completed without report should not switch views yet")
	}

	updated, cmd := app.Update(ReportReadyMsg{Report: model.Report{
		SchemaVersion: model.SchemaVersion,
		Duration:      "250ms",
		Summary:       model.Summary{TotalFindings: 2},
	}})
	app = updated.(*App)

	if app.resultsView == nil {
		t.Fatal("resultsView should be initialized once the report arrives")
	}
	if cmd == nil {
		t.Fatal("report arrival after completion should switch to results")
	}

	app.Update(cmd())
	if app.activeView != ViewResults {
		t.Errorf("activeView = %d, want ViewResults after report arrival", app.activeView)
	}
}

func TestAuditFailed(t *testing.T) {
	app := newTestApp()
	app.auditRunning = true
	testErr := errors.New("something broke")

	app.handleBusEvent(progress.Event{Type: progress.EventAuditFailed, At: time.Now(), Err: testErr})

	if app.auditRunning {
		t.Error("auditRunning should be false after failure")
	}
	if app.auditError != testErr {
		t.Errorf("auditError = %v, want %v", app.auditError, testErr)
	}
}

func TestRecentEventsCappedByState(t *testing.T) {
	app := newTestApp()

	for i := 0; i < 250; i++ {
		app.handleBusEvent(progress.Event{Type: progress.EventFindingDiscovered, At: time.Now(), Severity: model.SeverityLow})
	}

	snap := app.state.Snapshot()
	if len(snap.RecentEvents) != 200 {
		t.Errorf("RecentEvents length = %d, want 200", len(snap.RecentEvents))
	}
}

func TestUnknownObservedAppendedToLog(t *testing.T) {
	app := newTestApp()
	app.handleBusEvent(progress.Event{Type: progress.EventUnknownObserved, At: time.Now(), Title: "unknown thing"})

	snap := app.state.Snapshot()
	if len(snap.RecentEvents) != 1 {
		t.Errorf("RecentEvents length = %d, want 1", len(snap.RecentEvents))
	}
}

func TestStageCompletedEvent(t *testing.T) {
	app := newTestApp()
	app.handleBusEvent(progress.Event{Type: progress.EventStageCompleted, At: time.Now(), Stage: progress.StageChecks})

	snap := app.state.Snapshot()
	if len(snap.RecentEvents) != 1 {
		t.Errorf("RecentEvents length = %d, want 1", len(snap.RecentEvents))
	}
}

func TestStateSnapshotPropagatedToScanView(t *testing.T) {
	app := newTestApp()

	app.handleBusEvent(progress.Event{
		Type:        progress.EventCheckRegistered,
		At:          time.Now(),
		ComponentID: "check-x",
	})
	app.handleBusEvent(progress.Event{
		Type:     progress.EventFindingDiscovered,
		At:       time.Now(),
		Severity: model.SeverityCritical,
	})

	snap := app.state.Snapshot()
	if len(snap.Checks) != 1 {
		t.Fatalf("expected 1 check, got %d", len(snap.Checks))
	}
	if snap.SeverityCounts[model.SeverityCritical] != 1 {
		t.Errorf("critical count = %d, want 1", snap.SeverityCounts[model.SeverityCritical])
	}
}

func TestFullAuditLifecycle(t *testing.T) {
	app := newTestApp()
	app.ready = true
	app.width = 100
	app.height = 40

	events := []progress.Event{
		{Type: progress.EventAuditStarted, At: time.Now(), Message: "/srv/app"},
		{Type: progress.EventStageStarted, At: time.Now(), Stage: progress.StageSetup},
		{Type: progress.EventContextResolved, At: time.Now(), AppName: "myapp", AppPath: "/srv/app", LaravelVersion: "10.0"},
		{Type: progress.EventStageCompleted, At: time.Now(), Stage: progress.StageSetup},
		{Type: progress.EventStageStarted, At: time.Now(), Stage: progress.StageChecks},
		{Type: progress.EventCheckRegistered, At: time.Now(), ComponentID: "app-debug"},
		{Type: progress.EventCheckStarted, At: time.Now(), ComponentID: "app-debug"},
		{Type: progress.EventFindingDiscovered, At: time.Now(), Severity: model.SeverityCritical, Title: "APP_DEBUG=true"},
		{Type: progress.EventCheckCompleted, At: time.Now(), ComponentID: "app-debug", Findings: 1},
		{Type: progress.EventStageCompleted, At: time.Now(), Stage: progress.StageChecks},
	}

	for _, event := range events {
		app.handleBusEvent(event)
	}

	snap := app.state.Snapshot()
	if snap.Context.AppName != "myapp" {
		t.Errorf("AppName = %q, want %q", snap.Context.AppName, "myapp")
	}
	if snap.SeverityCounts[model.SeverityCritical] != 1 {
		t.Error("expected 1 critical finding")
	}
	if len(snap.Checks) != 1 || snap.Checks[0].Status != progress.ComponentStatusCompleted {
		t.Error("check should be completed")
	}

	view := app.View()
	if view == "" {
		t.Error("View() during lifecycle should produce output")
	}
}
