package views

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/nagi1/larainspect/internal/model"
	"github.com/nagi1/larainspect/internal/progress"
)

func TestNewScanView(t *testing.T) {
	view := NewScanView(testTheme())
	if view == nil {
		t.Fatal("NewScanView returned nil")
	}
	if view.severityCounts == nil {
		t.Error("severityCounts map should be initialized")
	}
}

func TestScanViewSetSize(t *testing.T) {
	view := NewScanView(testTheme())
	view.SetSize(120, 40)
	if view.width != 120 || view.height != 40 {
		t.Errorf("SetSize: width=%d height=%d, want 120,40", view.width, view.height)
	}
}

func TestScanViewSetSizeWithAppInfo(t *testing.T) {
	view := NewScanView(testTheme())
	view.appName = "myapp"
	view.laravelVersion = "10.0"
	view.SetSize(100, 30)
	if view.width != 100 {
		t.Errorf("width = %d, want 100", view.width)
	}
}

func TestScanViewSetSizeSmallBody(t *testing.T) {
	view := NewScanView(testTheme())
	view.SetSize(40, 5)
	if view.width != 40 {
		t.Errorf("width = %d, want 40", view.width)
	}
}

func TestScanViewUpdateFromSnapshot(t *testing.T) {
	view := NewScanView(testTheme())
	view.UpdateFromSnapshot(progress.Snapshot{
		Checks: []progress.ComponentState{
			{Kind: progress.ComponentKindCheck, ID: "check-a", Status: progress.ComponentStatusRunning},
		},
	})
}

func TestScanViewUpdateStage(t *testing.T) {
	view := NewScanView(testTheme())
	view.UpdateFromSnapshot(progress.Snapshot{CurrentStage: progress.StageChecks})
	if view.currentStage != progress.StageChecks {
		t.Errorf("currentStage = %q, want %q", view.currentStage, progress.StageChecks)
	}
}

func TestScanViewUpdateStats(t *testing.T) {
	view := NewScanView(testTheme())
	view.UpdateFromSnapshot(progress.Snapshot{SeverityCounts: map[model.Severity]int{model.SeverityHigh: 2}})
	if view.severityCounts[model.SeverityHigh] != 2 {
		t.Error("severity counts not updated")
	}
}

func TestScanViewUpdateAppInfo(t *testing.T) {
	view := NewScanView(testTheme())
	view.UpdateFromSnapshot(progress.Snapshot{
		Context: progress.ContextSummary{
			AppName:        "myapp",
			AppPath:        "/srv/myapp",
			LaravelVersion: "10.0",
			PHPVersion:     "8.2",
			PackageCount:   50,
		},
	})
	if view.appName != "myapp" {
		t.Errorf("appName = %q, want %q", view.appName, "myapp")
	}
}

func TestScanViewUpdateEventLog(t *testing.T) {
	view := NewScanView(testTheme())
	view.UpdateFromSnapshot(progress.Snapshot{
		RecentEvents: []progress.Event{{Type: progress.EventAuditStarted}},
	})
}

func TestScanViewSetAuditComplete(t *testing.T) {
	view := NewScanView(testTheme())
	view.SetAuditComplete(true)
	if !view.auditComplete {
		t.Error("auditComplete should be true")
	}
}

func TestScanViewViewZero(t *testing.T) {
	view := NewScanView(testTheme())
	if out := view.View(0, 0); out != "" {
		t.Error("View(0,0) should return empty")
	}
}

func TestScanViewViewWithData(t *testing.T) {
	view := NewScanView(testTheme())
	view.SetSize(100, 30)
	view.UpdateFromSnapshot(progress.Snapshot{
		CurrentStage: progress.StageChecks,
		Context: progress.ContextSummary{
			AppName:        "app",
			AppPath:        "/srv/app",
			LaravelVersion: "10.0",
			PHPVersion:     "8.2",
			PackageCount:   100,
		},
	})
	if out := view.View(100, 30); out == "" {
		t.Error("View should produce output with data")
	}
}

func TestScanViewRenderAppInfoEmpty(t *testing.T) {
	view := NewScanView(testTheme())
	if info := view.renderAppInfo(80); info != "" {
		t.Error("renderAppInfo with no data should return empty")
	}
}

func TestScanViewRenderAppInfoPath(t *testing.T) {
	view := NewScanView(testTheme())
	view.appPath = "/srv/app"
	view.laravelVersion = "10.0"
	view.phpVersion = "8.2"
	view.packageCount = 50
	if info := view.renderAppInfo(80); info == "" {
		t.Error("renderAppInfo with path should produce output")
	}
}

func TestScanViewTick(t *testing.T) {
	view := NewScanView(testTheme())
	view.SetSize(100, 30)
	view.Tick(nil)
}

func TestScanViewHandleKey(t *testing.T) {
	view := NewScanView(testTheme())
	view.SetSize(100, 30)
	view.HandleKey(tea.KeyMsg{Type: tea.KeyDown})
}

func TestScanViewNarrowTerminalRenders(t *testing.T) {
	view := NewScanView(testTheme())
	view.SetSize(60, 20)
	view.UpdateFromSnapshot(progress.Snapshot{
		CurrentStage:   progress.StageChecks,
		SeverityCounts: map[model.Severity]int{model.SeverityHigh: 1},
		Checks: []progress.ComponentState{
			{Kind: progress.ComponentKindCheck, ID: "narrow-check", Status: progress.ComponentStatusRunning},
		},
	})
	if out := view.View(60, 20); out == "" {
		t.Error("ScanView should render on narrow (60-wide) terminals")
	}
}

func TestScanViewVeryNarrowStacksVertically(t *testing.T) {
	view := NewScanView(testTheme())
	view.SetSize(50, 20)
	view.UpdateFromSnapshot(progress.Snapshot{
		CurrentStage: progress.StageChecks,
		Checks: []progress.ComponentState{
			{Kind: progress.ComponentKindCheck, ID: "check-a", Status: progress.ComponentStatusPending},
		},
	})
	if out := view.View(50, 20); out == "" {
		t.Error("ScanView should render with stacked layout on very narrow terminals")
	}
}

func TestScanViewUnknownCountVisible(t *testing.T) {
	view := NewScanView(testTheme())
	view.SetSize(100, 30)
	view.UpdateFromSnapshot(progress.Snapshot{
		SeverityCounts:   map[model.Severity]int{model.SeverityHigh: 1},
		UnknownsObserved: 3,
	})
	if out := view.View(100, 30); !strings.Contains(out, "3") {
		t.Error("ScanView should display unknown count when unknowns > 0")
	}
}

func TestScanViewStatusBannerShownWhenComplete(t *testing.T) {
	view := NewScanView(testTheme())
	view.SetSize(100, 30)
	view.SetAuditComplete(true)
	view.UpdateFromSnapshot(progress.Snapshot{
		SeverityCounts: map[model.Severity]int{model.SeverityHigh: 2},
	})

	out := view.View(100, 30)
	if !strings.Contains(out, "Audit complete") {
		t.Error("ScanView should show completion banner when audit is complete")
	}
	if !strings.Contains(out, "Tab") {
		t.Error("ScanView should show Tab hint in completion banner")
	}
}

func TestScanViewStatusBannerShowsWorkingStateDuringAudit(t *testing.T) {
	view := NewScanView(testTheme())
	view.SetSize(100, 30)
	view.UpdateFromSnapshot(progress.Snapshot{CurrentStage: progress.StageChecks})

	out := view.View(100, 30)
	if strings.Contains(out, "Audit complete") {
		t.Error("ScanView should not show completion banner during audit")
	}
	if !strings.Contains(out, "Working: Checks") {
		t.Error("ScanView should show a working status during audit")
	}
}

func TestScanViewShowsEmptyPanelGuidance(t *testing.T) {
	view := NewScanView(testTheme())
	view.SetSize(100, 30)

	out := view.View(100, 30)
	if !strings.Contains(out, "Waiting for checks") {
		t.Error("ScanView should explain an empty components panel")
	}
	if !strings.Contains(out, "Waiting for the first audit") {
		t.Error("ScanView should explain an empty event log")
	}
}
