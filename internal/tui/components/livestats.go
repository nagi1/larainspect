package components

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/nagi1/larainspect/internal/model"
	"github.com/nagi1/larainspect/internal/tui/theme"
)

// RenderLiveStats renders horizontal severity count badges.
func RenderLiveStats(counts map[model.Severity]int, t *theme.Theme, width int) string {
	severities := theme.OrderedSeverities()

	var badges []string
	for _, sev := range severities {
		count := counts[sev]
		style := t.SeverityStyles[sev]
		badge := style.Render(fmt.Sprintf(" %s: %d ", theme.SeverityLabel(sev), count))
		badges = append(badges, badge)
	}

	separator := t.Muted.Render("  ")
	row := strings.Join(badges, separator)

	return lipgloss.PlaceHorizontal(width, lipgloss.Center, row)
}

// RenderTotalFindings renders a compact total count.
func RenderTotalFindings(total int, t *theme.Theme) string {
	return t.Bold.Render(fmt.Sprintf("%d findings", total))
}
