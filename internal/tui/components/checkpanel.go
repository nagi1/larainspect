package components

import (
	"fmt"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/nagi1/larainspect/internal/progress"
	"github.com/nagi1/larainspect/internal/tui/theme"
)

// CheckPanel displays check/correlator statuses with spinners for running items.
type CheckPanel struct {
	checks  []progress.ComponentState
	spinner spinner.Model
	theme   *theme.Theme
	width   int
	height  int
}

// NewCheckPanel creates a new check panel.
func NewCheckPanel(t *theme.Theme) *CheckPanel {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(t.Colors.StageActive)
	return &CheckPanel{theme: t, spinner: s}
}

// SetChecks updates the component list.
func (p *CheckPanel) SetChecks(checks []progress.ComponentState) {
	p.checks = checks
}

// SetSize updates the panel dimensions.
func (p *CheckPanel) SetSize(w, h int) {
	p.width = w
	p.height = h
}

// Tick advances the spinner animation.
func (p *CheckPanel) Tick(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	p.spinner, cmd = p.spinner.Update(msg)
	return cmd
}

// View renders the check panel.
func (p *CheckPanel) View() string {
	title := p.theme.Subtitle.Render("  Components")
	rows := []string{title, ""}

	if len(p.checks) == 0 {
		rows = append(rows,
			p.theme.Muted.Render("  Waiting for checks and correlators..."),
			p.theme.Muted.Render("  Discovery may still be collecting evidence."),
		)
	}

	for _, comp := range p.checks {
		var statusIcon string
		switch comp.Status {
		case progress.ComponentStatusPending:
			statusIcon = p.theme.PendingStage.Render("○")
		case progress.ComponentStatusRunning:
			statusIcon = p.spinner.View()
		case progress.ComponentStatusCompleted:
			statusIcon = p.theme.SuccessStyle.Render("✓")
		case progress.ComponentStatusFailed:
			statusIcon = p.theme.ErrorStyle.Render("✗")
		}

		findingBadge := ""
		if comp.Findings > 0 {
			findingBadge = p.theme.Muted.Render(fmt.Sprintf(" (%d)", comp.Findings))
		}
		unknownBadge := ""
		if comp.Unknowns > 0 {
			unknownBadge = p.theme.WarningStyle.Render(fmt.Sprintf(" %d?", comp.Unknowns))
		}

		// Show kind label for correlators to distinguish from checks.
		kindLabel := ""
		if comp.Kind == progress.ComponentKindCorrelator {
			kindLabel = p.theme.Muted.Render("↔ ")
		}

		name := comp.ID
		if comp.Status == progress.ComponentStatusRunning {
			name = p.theme.Bold.Render(comp.ID)
		}

		// Truncate name on narrow panels.
		maxNameLen := p.width - 16
		if maxNameLen < 10 {
			maxNameLen = 10
		}
		if len(comp.ID) > maxNameLen {
			name = comp.ID[:maxNameLen-2] + ".."
			if comp.Status == progress.ComponentStatusRunning {
				name = p.theme.Bold.Render(name)
			}
		}

		row := fmt.Sprintf("  %s %s%s%s%s", statusIcon, kindLabel, name, findingBadge, unknownBadge)
		rows = append(rows, row)
	}

	content := lipgloss.JoinVertical(lipgloss.Left, rows...)

	return p.theme.SidePanel.
		Width(p.width).
		Height(p.height).
		Render(content)
}
