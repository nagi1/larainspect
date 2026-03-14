package tui

import (
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/nagi1/larainspect/internal/model"
	"github.com/nagi1/larainspect/internal/progress"
	"github.com/nagi1/larainspect/internal/tui/views"
)

func TestEscapeFromResultsSwitchesToScan(t *testing.T) {
	app := newTestApp()
	app.ready = true
	app.activeView = ViewResults

	app.Update(tea.KeyMsg{Type: tea.KeyEscape})

	if app.activeView != ViewScan {
		t.Errorf("activeView = %d, want ViewScan after Escape from Results", app.activeView)
	}
}

func TestEscapeFromScanDoesNothing(t *testing.T) {
	app := newTestApp()
	app.activeView = ViewScan

	app.Update(tea.KeyMsg{Type: tea.KeyEscape})

	if app.activeView != ViewScan {
		t.Errorf("activeView = %d, want ViewScan (unchanged)", app.activeView)
	}
}

func TestTabFromScanToResults(t *testing.T) {
	app := newTestApp()
	app.auditComplete = true
	app.activeView = ViewScan

	app.Update(tea.KeyMsg{Type: tea.KeyTab})

	if app.activeView != ViewResults {
		t.Errorf("activeView = %d, want ViewResults after Tab when complete", app.activeView)
	}
}

func TestTabFromScanWhenNotComplete(t *testing.T) {
	app := newTestApp()
	app.activeView = ViewScan

	app.Update(tea.KeyMsg{Type: tea.KeyTab})

	if app.activeView != ViewScan {
		t.Errorf("activeView = %d, want ViewScan (audit not complete)", app.activeView)
	}
}

func TestSwitchViewMsg(t *testing.T) {
	app := newTestApp()
	app.activeView = ViewScan

	app.Update(switchViewMsg{view: ViewResults})

	if app.activeView != ViewResults {
		t.Errorf("activeView = %d, want ViewResults", app.activeView)
	}
}

func TestDelegateKeyToViewScan(t *testing.T) {
	app := newTestApp()
	app.activeView = ViewScan
	app.width = 100
	app.height = 40

	cmd := app.delegateKeyToView(tea.KeyMsg{Type: tea.KeyDown})
	if cmd != nil {
		t.Error("delegateKeyToView(scan) should return nil")
	}
}

func TestDelegateKeyToViewResultsNil(t *testing.T) {
	app := newTestApp()
	app.activeView = ViewResults

	cmd := app.delegateKeyToView(tea.KeyMsg{Type: tea.KeyDown})
	if cmd != nil {
		t.Error("delegateKeyToView(results nil) should return nil")
	}
}

func TestDelegateKeyToViewResultsSet(t *testing.T) {
	app := newTestApp()
	app.activeView = ViewResults
	app.resultsView = views.NewResultsView(app.theme, views.ResultsData{Duration: time.Second})

	app.delegateKeyToView(tea.KeyMsg{Type: tea.KeyDown})
}

func TestUpdateTickMsg(t *testing.T) {
	app := newTestApp()
	app.activeView = ViewScan

	_, cmd := app.Update(tickMsg(time.Now()))
	if cmd == nil {
		t.Error("tickMsg should produce a batch command")
	}
}

func TestUpdateTickMsgNonScan(t *testing.T) {
	app := newTestApp()
	app.activeView = ViewResults

	_, cmd := app.Update(tickMsg(time.Now()))
	if cmd == nil {
		t.Error("tickMsg should still produce a command even in results view")
	}
}

func TestUpdateBusEventMsg(t *testing.T) {
	app := newTestApp()
	_, cmd := app.Update(BusEventMsg{Event: progress.Event{Type: progress.EventAuditStarted, At: time.Now()}})

	if !app.auditRunning {
		t.Error("BusEventMsg should trigger handleBusEvent")
	}
	_ = cmd
}

func TestUpdateArbitraryKeyDelegates(t *testing.T) {
	app := newTestApp()
	app.activeView = ViewScan
	app.width = 100
	app.height = 40

	app.Update(tea.KeyMsg{Type: tea.KeyDown})
}

func TestTabFromResultsDelegates(t *testing.T) {
	app := newTestApp()
	app.activeView = ViewResults
	app.resultsView = views.NewResultsView(app.theme, views.ResultsData{Duration: time.Second})

	app.Update(tea.KeyMsg{Type: tea.KeyTab})
}

func TestTabFromResultsWithoutResultsViewDoesNotPanic(t *testing.T) {
	app := newTestApp()
	app.activeView = ViewResults

	_, cmd := app.Update(tea.KeyMsg{Type: tea.KeyTab})
	if cmd != nil {
		t.Error("tab in results view without resultsView should not return a command")
	}
}

func TestHandleTabKeyNotCompleteNotResults(t *testing.T) {
	app := newTestApp()
	app.activeView = ViewScan

	cmd := app.handleTabKey(tea.KeyMsg{Type: tea.KeyTab})
	if cmd != nil {
		t.Error("tab when not complete and in scan should return nil")
	}
}

func TestRenderHeader(t *testing.T) {
	app := newTestApp()
	app.width = 100

	header := app.renderHeader()
	if header == "" {
		t.Error("renderHeader should return non-empty string")
	}
}

func TestRenderFooter(t *testing.T) {
	app := newTestApp()
	app.width = 100

	footer := app.renderFooter()
	if footer == "" {
		t.Error("renderFooter should return non-empty string")
	}
}

func TestPropagateSize(t *testing.T) {
	app := newTestApp()
	app.width = 120
	app.height = 40

	app.propagateSize()
}

func TestPropagateSizeWithResultsView(t *testing.T) {
	app := newTestApp()
	app.width = 120
	app.height = 40
	app.resultsView = views.NewResultsView(app.theme, views.ResultsData{Duration: time.Second})

	app.propagateSize()
}

func TestResizeNarrowTerminal(t *testing.T) {
	app := newTestApp()
	app.ready = true

	app.Update(tea.WindowSizeMsg{Width: 50, Height: 15})

	if app.width != 50 {
		t.Errorf("width = %d, want 50", app.width)
	}
	if view := app.View(); view == "" {
		t.Error("View() at narrow width should not be empty")
	}
}

func TestResizeVerySmallTerminal(t *testing.T) {
	app := newTestApp()
	app.ready = true
	app.width = 30
	app.height = 10

	app.propagateSize()

	if view := app.View(); view == "" {
		t.Error("View() at very small dimensions should not be empty")
	}
}

func TestResultsViewStateCanBeRenderedFromApp(t *testing.T) {
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

	if view := app.View(); view == "" {
		t.Error("View() with populated results view should not be empty")
	}
}
