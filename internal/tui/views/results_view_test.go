package views

import (
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/nagi1/larainspect/internal/model"
)

func TestNewResultsViewEmpty(t *testing.T) {
	view := NewResultsView(testTheme(), ResultsData{Duration: 5 * time.Second})
	if view == nil {
		t.Fatal("NewResultsView returned nil")
	}
}

func TestNewResultsViewWithFindings(t *testing.T) {
	findings := []model.Finding{
		{Title: "Debug enabled", Severity: model.SeverityCritical, Class: model.FindingClassDirect, CheckID: "app-debug", Confidence: model.ConfidenceConfirmed},
		{Title: "Weak key", Severity: model.SeverityHigh, Class: model.FindingClassHeuristic, CheckID: "app-key", Confidence: model.ConfidenceProbable},
		{Title: "Info leak", Severity: model.SeverityLow, Class: model.FindingClassDirect, CheckID: "info", Confidence: model.ConfidencePossible},
	}

	view := NewResultsView(testTheme(), ResultsData{
		Findings: findings,
		Duration: 2 * time.Second,
		Summary:  model.Summary{TotalFindings: 3, DirectFindings: 2, HeuristicFindings: 1},
	})

	if len(view.findings) != 3 {
		t.Errorf("findings count = %d, want 3", len(view.findings))
	}
}

func TestResultsViewSetSize(t *testing.T) {
	view := NewResultsView(testTheme(), ResultsData{Duration: time.Second})
	view.SetSize(120, 40)
	if view.width != 120 || view.height != 40 {
		t.Errorf("SetSize: width=%d height=%d, want 120,40", view.width, view.height)
	}
}

func TestResultsViewSetSizeSmallBody(t *testing.T) {
	view := NewResultsView(testTheme(), ResultsData{Duration: time.Second})
	view.SetSize(50, 8)
	if view.width != 50 {
		t.Errorf("width = %d, want 50", view.width)
	}
}

func TestResultsViewViewZero(t *testing.T) {
	view := NewResultsView(testTheme(), ResultsData{Duration: time.Second})
	if out := view.View(0, 0); out != "" {
		t.Error("View(0,0) should return empty")
	}
}

func TestResultsViewViewNonZero(t *testing.T) {
	view := NewResultsView(testTheme(), ResultsData{
		Findings: []model.Finding{
			{Title: "Test", Severity: model.SeverityHigh, CheckID: "test-check"},
		},
		Duration: time.Second,
		Summary:  model.Summary{TotalFindings: 1},
	})
	view.SetSize(100, 30)
	if out := view.View(100, 30); out == "" {
		t.Error("View should produce output for non-zero dimensions")
	}
}

func TestResultsViewNarrowTerminalRenders(t *testing.T) {
	view := NewResultsView(testTheme(), ResultsData{
		Findings: []model.Finding{
			{Title: "Test finding", Severity: model.SeverityHigh, CheckID: "test"},
		},
		Duration: time.Second,
		Summary:  model.Summary{TotalFindings: 1},
	})
	view.SetSize(60, 20)
	if out := view.View(60, 20); out == "" {
		t.Error("ResultsView should render on narrow (60-wide) terminals")
	}
}

func TestResultsViewHandleKeyTab(t *testing.T) {
	view := NewResultsView(testTheme(), ResultsData{Duration: time.Second})
	view.SetSize(100, 30)

	msg := tea.KeyMsg{Type: tea.KeyTab}
	view.HandleKey(msg)
	if view.focusPanel != 1 {
		t.Errorf("focusPanel = %d, want 1 after tab", view.focusPanel)
	}
	if view.table.Focused() {
		t.Error("table should be blurred when detail panel is focused")
	}

	view.HandleKey(msg)
	if view.focusPanel != 0 {
		t.Errorf("focusPanel = %d, want 0 after second tab", view.focusPanel)
	}
	if !view.table.Focused() {
		t.Error("table should be focused when findings panel is focused")
	}
}

func TestResultsViewHandleKeyTabWidensDetailPanel(t *testing.T) {
	view := NewResultsView(testTheme(), ResultsData{
		Findings: []model.Finding{
			{Title: "Test finding", Severity: model.SeverityHigh, CheckID: "test"},
		},
		Duration: time.Second,
	})
	view.SetSize(120, 30)

	initialTableWidth := view.table.Width()
	initialDetailWidth := view.detail.View()

	view.HandleKey(tea.KeyMsg{Type: tea.KeyTab})

	if view.table.Width() >= initialTableWidth {
		t.Fatalf("table width = %d, want less than %d when detail panel gains focus", view.table.Width(), initialTableWidth)
	}
	if view.detail.View() == initialDetailWidth {
		t.Fatal("detail view should change when the panel is widened and focused")
	}
}

func TestResultsViewHandleKeySortCycling(t *testing.T) {
	view := NewResultsView(testTheme(), ResultsData{
		Findings: []model.Finding{
			{Title: "A", Severity: model.SeverityCritical, Class: model.FindingClassDirect, CheckID: "z"},
			{Title: "B", Severity: model.SeverityLow, Class: model.FindingClassHeuristic, CheckID: "a"},
		},
		Duration: time.Second,
	})

	if view.sortColumn != SortBySeverity {
		t.Errorf("initial sort = %d, want SortBySeverity", view.sortColumn)
	}

	msg := tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}}
	view.HandleKey(msg)
	if view.sortColumn != SortByClass {
		t.Errorf("sort after s = %d, want SortByClass", view.sortColumn)
	}

	view.HandleKey(msg)
	if view.sortColumn != SortByCheckID {
		t.Errorf("sort after 2nd s = %d, want SortByCheckID", view.sortColumn)
	}

	view.HandleKey(msg)
	if view.sortColumn != SortBySeverity {
		t.Errorf("sort after 3rd s = %d, want SortBySeverity (wrap)", view.sortColumn)
	}
}

func TestResultsViewHandleKeyTableNavigation(t *testing.T) {
	view := NewResultsView(testTheme(), ResultsData{
		Findings: []model.Finding{
			{Title: "First", Severity: model.SeverityHigh, CheckID: "a"},
			{Title: "Second", Severity: model.SeverityLow, CheckID: "b"},
		},
		Duration: time.Second,
	})
	view.SetSize(100, 30)
	view.focusPanel = 0

	view.HandleKey(tea.KeyMsg{Type: tea.KeyDown})
}

func TestResultsViewHandleKeyFindingsPanelHorizontalPan(t *testing.T) {
	view := NewResultsView(testTheme(), ResultsData{
		Findings: []model.Finding{
			{
				Title:      strings.Repeat("ExtremelyLongFindingTitle", 3),
				Severity:   model.SeverityHigh,
				Class:      model.FindingClassDirect,
				CheckID:    "filesystem.permissions.world.writable.storage.logs",
				Confidence: model.ConfidenceConfirmed,
			},
		},
		Duration: time.Second,
	})
	view.SetSize(84, 24)
	view.focusPanel = 0
	view.syncPanelFocus()

	if view.maxTableHorizontalOffset() == 0 {
		t.Fatal("expected findings table to have horizontal overflow")
	}

	initial := view.renderTable()
	view.HandleKey(tea.KeyMsg{Type: tea.KeyRight})
	if view.horizontalOffset == 0 {
		t.Fatal("expected right key to increase findings horizontal offset")
	}
	if view.renderTable() == initial {
		t.Fatal("expected findings table rendering to change after horizontal pan")
	}

	view.HandleKey(tea.KeyMsg{Type: tea.KeyEnd})
	if view.horizontalOffset != view.maxTableHorizontalOffset() {
		t.Fatalf("horizontalOffset = %d, want %d after End", view.horizontalOffset, view.maxTableHorizontalOffset())
	}

	view.HandleKey(tea.KeyMsg{Type: tea.KeyHome})
	if view.horizontalOffset != 0 {
		t.Fatalf("horizontalOffset = %d, want 0 after Home", view.horizontalOffset)
	}
}

func TestResultsViewHandleKeyDetailPanel(t *testing.T) {
	view := NewResultsView(testTheme(), ResultsData{
		Findings: []model.Finding{
			{
				Title:       strings.Repeat("Long detail title ", 4),
				Severity:    model.SeverityHigh,
				Class:       model.FindingClassDirect,
				Confidence:  model.ConfidenceConfirmed,
				CheckID:     "detail-panel",
				Why:         "why",
				Remediation: "fix",
			},
		},
		Duration: time.Second,
	})
	view.SetSize(100, 30)
	view.focusPanel = 1
	view.syncPanelFocus()

	initialOffset := view.detail.View()
	view.HandleKey(tea.KeyMsg{Type: tea.KeyRight})
	if view.detail.View() == initialOffset {
		t.Error("detail panel should respond to horizontal pan keys when focused")
	}
}

func TestResultsViewRenderSummaryWithApp(t *testing.T) {
	view := NewResultsView(testTheme(), ResultsData{
		AppName:  "testapp",
		Duration: 500 * time.Millisecond,
		Summary: model.Summary{
			TotalFindings:        3,
			DirectFindings:       2,
			HeuristicFindings:    1,
			CompromiseIndicators: 0,
			Unknowns:             1,
		},
	})
	view.SetSize(100, 30)

	summary := view.renderSummary(100)
	if summary == "" {
		t.Error("renderSummary should not be empty")
	}
}

func TestResultsViewAdaptiveColumnsWide(t *testing.T) {
	view := NewResultsView(testTheme(), ResultsData{
		Findings: []model.Finding{{Title: "Test", Severity: model.SeverityHigh, CheckID: "test"}},
		Duration: time.Second,
	})
	view.SetSize(180, 40)

	cols := view.adaptiveColumns()
	if cols[3].Width < 20 {
		t.Errorf("title column width = %d, should be generous on wide terminals", cols[3].Width)
	}
}

func TestResultsViewAdaptiveColumnsNarrow(t *testing.T) {
	view := NewResultsView(testTheme(), ResultsData{
		Findings: []model.Finding{{Title: "Test", Severity: model.SeverityHigh, CheckID: "test"}},
		Duration: time.Second,
	})
	view.SetSize(80, 20)

	cols := view.adaptiveColumns()
	if cols[3].Width < 12 {
		t.Errorf("title column width = %d, should be at least 12", cols[3].Width)
	}
}

func TestResultsViewUnknownsSummaryRendered(t *testing.T) {
	view := NewResultsView(testTheme(), ResultsData{
		Findings: []model.Finding{{Title: "Finding", Severity: model.SeverityHigh, CheckID: "test"}},
		Unknowns: []model.Unknown{
			{Title: "Unknown item A"},
			{Title: "Unknown item B"},
		},
		Duration: time.Second,
		Summary:  model.Summary{TotalFindings: 1, Unknowns: 2},
	})
	view.SetSize(100, 30)

	out := view.View(100, 30)
	if !strings.Contains(out, "unknowns") {
		t.Error("ResultsView should show unknowns summary when unknowns present")
	}
}

func TestResultsViewNoUnknownsSummaryWhenEmpty(t *testing.T) {
	view := NewResultsView(testTheme(), ResultsData{
		Findings: []model.Finding{{Title: "Finding", Severity: model.SeverityHigh, CheckID: "test"}},
		Duration: time.Second,
		Summary:  model.Summary{TotalFindings: 1},
	})
	view.SetSize(100, 30)

	out := view.View(100, 30)
	if strings.Contains(out, "could not be fully evaluated") {
		t.Error("ResultsView should not show unknowns section when no unknowns exist")
	}
}

func TestResultsViewViewShowsNavigationHints(t *testing.T) {
	view := NewResultsView(testTheme(), ResultsData{
		Findings: []model.Finding{
			{Title: "Finding", Severity: model.SeverityHigh, CheckID: "test"},
		},
		Duration: time.Second,
		Summary:  model.Summary{TotalFindings: 1},
	})
	view.SetSize(120, 30)

	out := view.View(120, 30)
	if !strings.Contains(out, "Tab switch") {
		t.Error("results view should show tab navigation hint")
	}
	if !strings.Contains(out, "Pan") {
		t.Error("results view should show detail pan hint")
	}
	if !strings.Contains(out, "Home/End") {
		t.Error("results view should show Home/End pan hint")
	}
}

func TestResultsViewSortDirectionToggle(t *testing.T) {
	view := NewResultsView(testTheme(), ResultsData{
		Findings: []model.Finding{
			{Title: "A", Severity: model.SeverityCritical, CheckID: "z"},
			{Title: "B", Severity: model.SeverityLow, CheckID: "a"},
		},
		Duration: time.Second,
	})
	view.SetSize(100, 30)

	if view.sortAscending {
		t.Error("initial sort should be descending")
	}

	sKey := tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}}
	view.HandleKey(sKey)
	view.HandleKey(sKey)
	view.HandleKey(sKey)
	view.HandleKey(sKey)
	view.HandleKey(sKey)
	view.HandleKey(sKey)

	prevColumn := view.sortColumn
	view.HandleKey(sKey)
	if view.sortColumn == prevColumn && !view.sortAscending {
		t.Error("pressing sort on same column should toggle direction")
	}
}
