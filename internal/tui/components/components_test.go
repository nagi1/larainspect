package components

import (
	"strings"
	"testing"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/nagi1/larainspect/internal/model"
	"github.com/nagi1/larainspect/internal/progress"
	"github.com/nagi1/larainspect/internal/tui/theme"
)

func testTheme() *theme.Theme {
	return theme.DefaultTheme()
}

func TestRenderSeverityBadgeKnownSeverity(t *testing.T) {
	th := testTheme()
	severities := theme.OrderedSeverities()
	for _, sev := range severities {
		badge := RenderSeverityBadge(sev, th)
		if badge == "" {
			t.Errorf("RenderSeverityBadge(%q) returned empty string", sev)
		}
	}
}

func TestRenderSeverityBadgeUnknownSeverity(t *testing.T) {
	th := testTheme()
	badge := RenderSeverityBadge("custom", th)
	if badge != "custom" {
		t.Errorf("unknown severity badge = %q, want %q", badge, "custom")
	}
}

func TestRenderLiveStats(t *testing.T) {
	th := testTheme()
	counts := map[model.Severity]int{
		model.SeverityCritical: 2,
		model.SeverityHigh:     5,
	}
	out := RenderLiveStats(counts, th, 80)
	if out == "" {
		t.Error("RenderLiveStats returned empty string")
	}
}

func TestRenderLiveStatsZeroCounts(t *testing.T) {
	th := testTheme()
	empty := map[model.Severity]int{}
	out := RenderLiveStats(empty, th, 80)
	if out == "" {
		t.Error("RenderLiveStats with zero counts returned empty string")
	}
}

func TestRenderTotalFindings(t *testing.T) {
	th := testTheme()
	out := RenderTotalFindings(42, th)
	if out == "" {
		t.Error("RenderTotalFindings returned empty string")
	}
}

func TestRenderStageProgress(t *testing.T) {
	th := testTheme()
	out := RenderStageProgress(progress.StageChecks, false, th, 120)
	if out == "" {
		t.Error("RenderStageProgress returned empty string")
	}
}

func TestRenderStageProgressComplete(t *testing.T) {
	th := testTheme()
	out := RenderStageProgress(progress.StageReport, true, th, 120)
	if out == "" {
		t.Error("RenderStageProgress (complete) returned empty string")
	}
}

func TestStageIndex(t *testing.T) {
	idx := stageIndex(progress.StageSetup)
	if idx != 0 {
		t.Errorf("stageIndex(StageSetup) = %d, want 0", idx)
	}
	idx = stageIndex(progress.StageReport)
	if idx < 0 {
		t.Error("stageIndex(StageReport) should be >= 0")
	}
	idx = stageIndex("nonexistent")
	if idx != -1 {
		t.Errorf("stageIndex(nonexistent) = %d, want -1", idx)
	}
}

func TestRenderHeader(t *testing.T) {
	th := testTheme()
	data := HeaderData{
		AppName:        "myapp",
		AppPath:        "/srv/myapp",
		LaravelVersion: "10.0.0",
		PHPVersion:     "8.2.0",
		PackageCount:   100,
		ToolVersion:    "1.0.0",
		AuditRunning:   true,
	}
	out := RenderHeader(data, th, 120)
	if out == "" {
		t.Error("RenderHeader returned empty string")
	}
}

func TestRenderHeaderMinimalData(t *testing.T) {
	th := testTheme()
	data := HeaderData{ToolVersion: "dev"}
	out := RenderHeader(data, th, 80)
	if out == "" {
		t.Error("RenderHeader with minimal data returned empty string")
	}
}

func TestRenderHeaderStatusVariants(t *testing.T) {
	th := testTheme()
	tests := []struct {
		name string
		data HeaderData
	}{
		{"ready", HeaderData{ToolVersion: "dev"}},
		{"running", HeaderData{ToolVersion: "dev", AuditRunning: true}},
		{"complete", HeaderData{ToolVersion: "dev", AuditComplete: true}},
		{"error", HeaderData{ToolVersion: "dev", AuditError: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := RenderHeader(tt.data, th, 100)
			if out == "" {
				t.Errorf("RenderHeader(%s) returned empty", tt.name)
			}
		})
	}
}

func TestRenderFooter(t *testing.T) {
	th := testTheme()
	h := help.New()
	// Use a simple KeyMap that satisfies help.KeyMap
	keys := simpleKeyMap{}
	out := RenderFooter(h, keys, th, 80)
	if out == "" {
		t.Error("RenderFooter returned empty string")
	}
	sep := RenderSeparator(th, 80)
	if sep == "" {
		t.Error("RenderSeparator returned empty string")
	}
}

// simpleKeyMap satisfies help.KeyMap for testing purposes.
type simpleKeyMap struct{}

func (s simpleKeyMap) ShortHelp() []key.Binding {
	return []key.Binding{key.NewBinding(key.WithKeys("q"), key.WithHelp("q", "quit"))}
}
func (s simpleKeyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{s.ShortHelp()}
}

func TestCheckPanelView(t *testing.T) {
	th := testTheme()
	panel := NewCheckPanel(th)
	panel.SetSize(40, 20)

	checks := []progress.ComponentState{
		{Kind: progress.ComponentKindCheck, ID: "check-a", Status: progress.ComponentStatusPending},
		{Kind: progress.ComponentKindCheck, ID: "check-b", Status: progress.ComponentStatusRunning},
		{Kind: progress.ComponentKindCheck, ID: "check-c", Status: progress.ComponentStatusCompleted, Findings: 3},
		{Kind: progress.ComponentKindCheck, ID: "check-d", Status: progress.ComponentStatusFailed},
		{Kind: progress.ComponentKindCorrelator, ID: "corr-a", Status: progress.ComponentStatusCompleted, Unknowns: 2},
	}
	panel.SetChecks(checks)

	out := panel.View()
	if out == "" {
		t.Error("CheckPanel.View() returned empty string")
	}
}

func TestEventLogView(t *testing.T) {
	th := testTheme()
	log := NewEventLog(th)
	log.SetSize(80, 20)

	events := []progress.Event{
		{Type: progress.EventAuditStarted, Message: "starting"},
		{Type: progress.EventCheckStarted, ComponentID: "check-a"},
		{Type: progress.EventFindingDiscovered, Severity: model.SeverityHigh, Title: "test finding"},
		{Type: progress.EventAuditCompleted, Findings: 1},
	}
	log.SetEvents(events)

	out := log.View()
	if out == "" {
		t.Error("EventLog.View() returned empty string")
	}
}

func TestEventTypeIcons(t *testing.T) {
	th := testTheme()
	eventTypes := []progress.EventType{
		progress.EventAuditStarted,
		progress.EventAuditCompleted,
		progress.EventAuditFailed,
		progress.EventStageStarted,
		progress.EventStageCompleted,
		progress.EventCheckRegistered,
		progress.EventCheckStarted,
		progress.EventCheckCompleted,
		progress.EventCheckFailed,
		progress.EventCorrelatorRegistered,
		progress.EventCorrelatorStarted,
		progress.EventCorrelatorCompleted,
		progress.EventCorrelatorFailed,
		progress.EventFindingDiscovered,
		progress.EventUnknownObserved,
		"unknown.type",
	}
	for _, et := range eventTypes {
		icon := eventTypeIcon(et, th)
		if icon == "" {
			t.Errorf("eventTypeIcon(%q) returned empty string", et)
		}
	}
}

func TestFormatEventMessage(t *testing.T) {
	tests := []progress.Event{
		{Type: progress.EventAuditStarted, Message: "begin"},
		{Type: progress.EventAuditCompleted, Findings: 5, Unknowns: 2},
		{Type: progress.EventAuditFailed, Err: nil},
		{Type: progress.EventStageStarted, Stage: progress.StageChecks},
		{Type: progress.EventStageCompleted, Stage: progress.StageChecks},
		{Type: progress.EventCheckRegistered, ComponentID: "check-a"},
		{Type: progress.EventCheckStarted, ComponentID: "check-a"},
		{Type: progress.EventCheckCompleted, ComponentID: "check-a", Findings: 3, Unknowns: 1},
		{Type: progress.EventCheckFailed, ComponentID: "check-a"},
		{Type: progress.EventCorrelatorRegistered, ComponentID: "corr-a"},
		{Type: progress.EventCorrelatorStarted, ComponentID: "corr-a"},
		{Type: progress.EventCorrelatorCompleted, ComponentID: "corr-a"},
		{Type: progress.EventCorrelatorFailed, ComponentID: "corr-a"},
		{Type: progress.EventFindingDiscovered, Severity: model.SeverityHigh, Title: "bad thing"},
		{Type: progress.EventUnknownObserved, Title: "unknown thing"},
		{Type: progress.EventContextResolved, Message: "context info"},
		{Type: "custom", Message: "custom message"},
		{Type: "custom"},
	}
	for _, ev := range tests {
		msg := formatEventMessage(ev)
		if msg == "" {
			t.Errorf("formatEventMessage(%q) returned empty string", ev.Type)
		}
	}
}

func TestFindingDetailRendersRelatedControls(t *testing.T) {
	th := testTheme()
	detail := NewFindingDetail(th)
	detail.SetSize(80, 20)
	detail.SetFinding(&model.Finding{
		ID:          "filesystem.permissions.runtime_owned_env.var.www.shop.env",
		CheckID:     "filesystem.permissions",
		Class:       model.FindingClassDirect,
		Severity:    model.SeverityHigh,
		Confidence:  model.ConfidenceConfirmed,
		Title:       ".env is runtime owned",
		Why:         "demo",
		Remediation: "fix it",
		Evidence:    []model.Evidence{{Label: "path", Detail: "/var/www/shop/.env"}},
	})

	out := detail.View()
	if !strings.Contains(out, "laravel.env-integrity-and-permissions") {
		t.Fatalf("expected related control in finding detail, got %q", out)
	}
}

func TestFindingDetailEmptyView(t *testing.T) {
	th := testTheme()
	detail := NewFindingDetail(th)
	detail.SetSize(60, 20)

	out := detail.View()
	if out == "" {
		t.Error("FindingDetail.View() without finding returned empty")
	}
}

func TestFindingDetailWithFinding(t *testing.T) {
	th := testTheme()
	detail := NewFindingDetail(th)
	detail.SetSize(60, 20)

	finding := &model.Finding{
		Title:       "Debug mode enabled",
		Severity:    model.SeverityCritical,
		Class:       model.FindingClassDirect,
		Confidence:  model.ConfidenceConfirmed,
		CheckID:     "app-debug",
		Why:         "This is a long explanation of why this is bad and should be fixed.",
		Remediation: "Set APP_DEBUG=false in .env",
		Evidence: []model.Evidence{
			{Label: "File", Detail: ".env"},
			{Label: "Value", Detail: "APP_DEBUG=true"},
		},
		Affected: []model.Target{
			{Type: "file", Name: ".env", Path: "/srv/app/.env"},
		},
	}
	detail.SetFinding(finding)

	out := detail.View()
	if out == "" {
		t.Error("FindingDetail.View() with finding returned empty")
	}
}

func TestWordWrap(t *testing.T) {
	tests := []struct {
		text  string
		width int
		lines int
	}{
		{"", 80, 0},
		{"short", 80, 1},
		{"word1 word2 word3 word4 word5", 10, 5},
	}
	for _, tt := range tests {
		result := wordWrap(tt.text, tt.width)
		if tt.lines == 0 && result != "" {
			t.Errorf("wordWrap(%q, %d) = %q, want empty", tt.text, tt.width, result)
		}
	}
}

func TestWordWrapZeroWidth(t *testing.T) {
	result := wordWrap("hello world", 0)
	if result != "hello world" {
		t.Errorf("wordWrap with zero width should return original, got %q", result)
	}
}

func TestCheckPanelTick(t *testing.T) {
	th := testTheme()
	panel := NewCheckPanel(th)
	panel.SetSize(40, 20)
	// Tick should not panic
	cmd := panel.Tick(nil)
	_ = cmd
}

func TestEventLogHandleKey(t *testing.T) {
	th := testTheme()
	log := NewEventLog(th)
	log.SetSize(80, 20)

	events := make([]progress.Event, 30)
	for i := range events {
		events[i] = progress.Event{Type: progress.EventFindingDiscovered, Severity: model.SeverityHigh, Title: "f"}
	}
	log.SetEvents(events)

	// Scroll down
	msg := tea.KeyMsg{Type: tea.KeyDown}
	log.HandleKey(msg)
	// Scroll up
	msg = tea.KeyMsg{Type: tea.KeyUp}
	log.HandleKey(msg)
}

func TestFindingDetailHandleKey(t *testing.T) {
	th := testTheme()
	detail := NewFindingDetail(th)
	detail.SetSize(60, 20)

	finding := &model.Finding{
		Title:       "Debug mode enabled",
		Severity:    model.SeverityCritical,
		Why:         "Long explanation that should produce scrollable content for testing purposes to ensure scrolling works correctly in the view.",
		Remediation: "Fix it.",
	}
	detail.SetFinding(finding)

	msg := tea.KeyMsg{Type: tea.KeyDown}
	detail.HandleKey(msg)
	msg = tea.KeyMsg{Type: tea.KeyUp}
	detail.HandleKey(msg)
}

func TestFindingDetailHandleKeyHorizontalPan(t *testing.T) {
	th := testTheme()
	detail := NewFindingDetail(th)
	detail.SetSize(36, 18)
	detail.SetFocused(true)

	finding := &model.Finding{
		Title:       strings.Repeat("VeryLongFindingTitle", 3),
		Severity:    model.SeverityHigh,
		Class:       model.FindingClassDirect,
		Confidence:  model.ConfidenceConfirmed,
		CheckID:     "detail-pan",
		Why:         "why",
		Remediation: "fix",
	}
	detail.SetFinding(finding)

	if detail.maxHorizontalOffset() == 0 {
		t.Fatal("expected horizontal overflow for long title")
	}

	initial := detail.viewport.View()
	detail.HandleKey(tea.KeyMsg{Type: tea.KeyRight})
	if detail.horizontalOffset == 0 {
		t.Fatal("expected right key to increase horizontal offset")
	}
	if detail.viewport.View() == initial {
		t.Fatal("expected viewport content to change after horizontal pan")
	}

	detail.HandleKey(tea.KeyMsg{Type: tea.KeyEnd})
	if detail.horizontalOffset != detail.maxHorizontalOffset() {
		t.Fatalf("horizontalOffset = %d, want %d after End", detail.horizontalOffset, detail.maxHorizontalOffset())
	}

	detail.HandleKey(tea.KeyMsg{Type: tea.KeyHome})
	if detail.horizontalOffset != 0 {
		t.Fatalf("horizontalOffset = %d, want 0 after Home", detail.horizontalOffset)
	}
}
