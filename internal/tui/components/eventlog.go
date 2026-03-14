package components

import (
	"fmt"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/nagi1/larainspect/internal/progress"
	"github.com/nagi1/larainspect/internal/tui/theme"
)

// EventLog is a scrollable event viewport.
type EventLog struct {
	viewport   viewport.Model
	events     []progress.Event
	theme      *theme.Theme
	autoScroll bool
	width      int
	height     int
}

// NewEventLog creates a new event log viewer.
func NewEventLog(t *theme.Theme) *EventLog {
	vp := viewport.New(80, 10)
	return &EventLog{
		viewport:   vp,
		theme:      t,
		autoScroll: true,
	}
}

// SetSize updates the viewport dimensions.
func (e *EventLog) SetSize(w, h int) {
	e.width = w
	e.height = h
	e.viewport.Width = w - 4
	e.viewport.Height = h - 2
}

// SetEvents replaces the event list and rebuilds the viewport content.
func (e *EventLog) SetEvents(events []progress.Event) {
	e.events = events
	e.rebuildContent()
}

func (e *EventLog) rebuildContent() {
	var lines []string
	for _, ev := range e.events {
		timestamp := e.theme.Muted.Render(ev.At.Format("15:04:05"))
		icon := eventTypeIcon(ev.Type, e.theme)
		msg := formatEventMessage(ev)
		line := fmt.Sprintf(" %s %s %s", timestamp, icon, msg)
		lines = append(lines, line)
	}

	content := lipgloss.JoinVertical(lipgloss.Left, lines...)
	e.viewport.SetContent(content)
	if e.autoScroll {
		e.viewport.GotoBottom()
	}
}

// HandleKey processes scrolling keys.
func (e *EventLog) HandleKey(msg tea.KeyMsg) {
	e.viewport, _ = e.viewport.Update(msg)
}

// View renders the event log.
func (e *EventLog) View() string {
	title := e.theme.Subtitle.Render("  Event Log")

	border := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(e.theme.Colors.Border).
		Width(e.width).
		Height(e.height)

	body := e.viewport.View()
	if len(e.events) == 0 {
		body = lipgloss.JoinVertical(
			lipgloss.Left,
			e.theme.Muted.Render("  Waiting for the first audit event..."),
			e.theme.Muted.Render("  Large discovery passes can take a bit."),
		)
	}

	content := lipgloss.JoinVertical(lipgloss.Left, title, "", body)
	return border.Render(content)
}

func eventTypeIcon(t progress.EventType, th *theme.Theme) string {
	switch t {
	case progress.EventAuditStarted:
		return th.AccentStyle.Render("▶")
	case progress.EventAuditCompleted:
		return th.SuccessStyle.Render("✓")
	case progress.EventAuditFailed:
		return th.ErrorStyle.Render("✗")
	case progress.EventStageStarted:
		return th.ActiveStage.Render("●")
	case progress.EventStageCompleted:
		return th.CompletedStage.Render("✓")
	case progress.EventCheckRegistered, progress.EventCorrelatorRegistered:
		return th.Muted.Render("+")
	case progress.EventCheckStarted, progress.EventCorrelatorStarted:
		return th.ActiveStage.Render("▸")
	case progress.EventCheckCompleted, progress.EventCorrelatorCompleted:
		return th.SuccessStyle.Render("✓")
	case progress.EventCheckFailed, progress.EventCorrelatorFailed:
		return th.ErrorStyle.Render("✗")
	case progress.EventFindingDiscovered:
		return th.WarningStyle.Render("▲")
	case progress.EventUnknownObserved:
		return th.Muted.Render("?")
	default:
		return " "
	}
}

func formatEventMessage(ev progress.Event) string {
	switch ev.Type {
	case progress.EventAuditStarted:
		return fmt.Sprintf("Audit started: %s", ev.Message)
	case progress.EventAuditCompleted:
		return fmt.Sprintf("Audit completed: %d findings, %d unknowns", ev.Findings, ev.Unknowns)
	case progress.EventAuditFailed:
		msg := "Audit failed"
		if ev.Err != nil {
			msg += ": " + ev.Err.Error()
		}
		return msg
	case progress.EventStageStarted:
		return fmt.Sprintf("%s started", ev.Stage.Label())
	case progress.EventStageCompleted:
		return fmt.Sprintf("%s complete", ev.Stage.Label())
	case progress.EventCheckRegistered:
		return fmt.Sprintf("Loaded check: %s", ev.ComponentID)
	case progress.EventCheckStarted:
		return fmt.Sprintf("Running: %s", ev.ComponentID)
	case progress.EventCheckCompleted:
		msg := fmt.Sprintf("Check done: %s", ev.ComponentID)
		if ev.Findings > 0 || ev.Unknowns > 0 {
			msg += fmt.Sprintf(" (%d findings, %d unknowns)", ev.Findings, ev.Unknowns)
		}
		return msg
	case progress.EventCheckFailed:
		return fmt.Sprintf("Check failed: %s", ev.ComponentID)
	case progress.EventCorrelatorRegistered:
		return fmt.Sprintf("Loaded correlator: %s", ev.ComponentID)
	case progress.EventCorrelatorStarted:
		return fmt.Sprintf("Correlating: %s", ev.ComponentID)
	case progress.EventCorrelatorCompleted:
		return fmt.Sprintf("Correlation done: %s", ev.ComponentID)
	case progress.EventCorrelatorFailed:
		return fmt.Sprintf("Correlator failed: %s", ev.ComponentID)
	case progress.EventFindingDiscovered:
		return fmt.Sprintf("[%s] %s", ev.Severity, ev.Title)
	case progress.EventUnknownObserved:
		return fmt.Sprintf("[unknown] %s", ev.Title)
	case progress.EventContextResolved:
		return ev.Message
	default:
		if ev.Message != "" {
			return ev.Message
		}
		return string(ev.Type)
	}
}
