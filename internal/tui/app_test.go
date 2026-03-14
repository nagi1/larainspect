package tui

import (
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/nagi1/larainspect/internal/model"
	"github.com/nagi1/larainspect/internal/progress"
	"github.com/nagi1/larainspect/internal/tui/views"
)

func newTestApp() *App {
	bus := progress.NewBus()
	return NewApp(bus, "1.0.0-test")
}

func TestNewAppInitialState(t *testing.T) {
	app := newTestApp()

	if app.activeView != ViewScan {
		t.Errorf("initial view = %d, want ViewScan", app.activeView)
	}
	if app.auditRunning {
		t.Error("auditRunning should be false initially")
	}
	if app.auditComplete {
		t.Error("auditComplete should be false initially")
	}
	if app.version != "1.0.0-test" {
		t.Errorf("version = %q, want %q", app.version, "1.0.0-test")
	}
	if app.state == nil {
		t.Error("state should not be nil")
	}

	snap := app.state.Snapshot()
	if len(snap.Checks) != 0 {
		t.Errorf("checks should be empty, got %d", len(snap.Checks))
	}
	if len(snap.RecentEvents) != 0 {
		t.Errorf("recentEvents should be empty, got %d", len(snap.RecentEvents))
	}
	if app.scanView == nil {
		t.Error("scanView should not be nil")
	}
	if app.resultsView != nil {
		t.Error("resultsView should be nil initially")
	}
}

func TestAppInitReturnsCommands(t *testing.T) {
	app := newTestApp()
	cmd := app.Init()
	if cmd == nil {
		t.Error("Init() should return a batch command")
	}
}

func TestAppViewBeforeReady(t *testing.T) {
	app := newTestApp()
	view := app.View()
	if view == "" {
		t.Error("View() before ready should return loading text")
	}
	if view != "\n  Starting Larainspect…" {
		t.Errorf("View() = %q, want loading message", view)
	}
}

func TestAppWindowSizeMarksReady(t *testing.T) {
	app := newTestApp()
	msg := tea.WindowSizeMsg{Width: 120, Height: 40}
	updated, _ := app.Update(msg)
	resizedApp := updated.(*App)

	if !resizedApp.ready {
		t.Error("app should be ready after WindowSizeMsg")
	}
	if resizedApp.width != 120 {
		t.Errorf("width = %d, want 120", resizedApp.width)
	}
	if resizedApp.height != 40 {
		t.Errorf("height = %d, want 40", resizedApp.height)
	}
}

func TestAppQuitKey(t *testing.T) {
	app := newTestApp()
	msg := tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}}
	_, cmd := app.Update(msg)
	if cmd == nil {
		t.Fatal("quit key should produce a command")
	}

	result := cmd()
	if _, ok := result.(tea.QuitMsg); !ok {
		t.Error("quit command should produce QuitMsg")
	}
}

func TestAppHelpToggle(t *testing.T) {
	app := newTestApp()
	initial := app.help.ShowAll

	msg := tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'?'}}
	app.Update(msg)
	if app.help.ShowAll == initial {
		t.Error("help toggle should flip ShowAll")
	}

	app.Update(msg)
	if app.help.ShowAll != initial {
		t.Error("second toggle should restore original state")
	}
}

func TestContentHeightMinimum(t *testing.T) {
	app := newTestApp()
	app.height = 5

	height := app.contentHeight("H", "F")
	if height < 4 {
		t.Errorf("contentHeight = %d, should be at least 4", height)
	}
}

func TestSetReport(t *testing.T) {
	app := newTestApp()
	if app.report != nil {
		t.Error("report should be nil initially")
	}

	report := model.Report{SchemaVersion: "test"}
	app.SetReport(report)

	if app.report == nil {
		t.Fatal("report should not be nil after SetReport")
	}
	if app.report.SchemaVersion != "test" {
		t.Errorf("report.SchemaVersion = %q, want %q", app.report.SchemaVersion, "test")
	}
}

func TestAuditCompleteAccessor(t *testing.T) {
	app := newTestApp()
	if app.AuditComplete() {
		t.Fatal("AuditComplete() should be false initially")
	}

	app.auditComplete = true
	if !app.AuditComplete() {
		t.Fatal("AuditComplete() should reflect completion state")
	}
}

func TestViewWhenReadyScanView(t *testing.T) {
	app := newTestApp()
	app.ready = true
	app.width = 100
	app.height = 40
	app.activeView = ViewScan

	view := app.View()
	if view == "" {
		t.Error("View() when ready should not be empty")
	}
}

func TestViewWhenReadyResultsViewNil(t *testing.T) {
	app := newTestApp()
	app.ready = true
	app.width = 100
	app.height = 40
	app.activeView = ViewResults

	view := app.View()
	if view == "" {
		t.Error("View() with ViewResults (nil resultsView) should not be empty")
	}
}

func TestViewWhenReadyResultsViewSet(t *testing.T) {
	app := newTestApp()
	app.ready = true
	app.width = 100
	app.height = 40
	app.activeView = ViewResults
	app.resultsView = views.NewResultsView(app.theme, views.ResultsData{
		Findings: []model.Finding{
			{Title: "Test", Severity: model.SeverityHigh, CheckID: "test"},
		},
		Duration: time.Second,
		Summary:  model.Summary{TotalFindings: 1},
	})

	view := app.View()
	if view == "" {
		t.Error("View() with results view should not be empty")
	}
}
