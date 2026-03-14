package components

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/nagi1/larainspect/internal/progress"
	"github.com/nagi1/larainspect/internal/tui/theme"
)

// RenderStageProgress renders a horizontal pipeline stage indicator.
//
// On narrow terminals (< 80 cols), uses compact single-char labels.
// Example full:    ✓ Setup  →  ✓ Discovery  →  ● Checks  →  ○ Correlation  →  ○ Post-Process  →  ○ Report
// Example compact: ✓S → ✓D → ●C → ○R → ○P → ○R
func RenderStageProgress(currentStage progress.Stage, auditComplete bool, t *theme.Theme, width int) string {
	stages := progress.OrderedStages()
	compact := width < 80
	var rendered []string

	for _, stage := range stages {
		var style lipgloss.Style
		var prefix string

		switch {
		case auditComplete:
			style = t.CompletedStage
			prefix = "✓ "
		case stageIndex(stage) < stageIndex(currentStage):
			style = t.CompletedStage
			prefix = "✓ "
		case stage == currentStage:
			style = t.ActiveStage
			prefix = "● "
		default:
			style = t.PendingStage
			prefix = "○ "
		}

		label := stage.Label()
		if compact {
			// Use first character of each stage label for narrow terminals.
			runes := []rune(label)
			if len(runes) > 0 {
				label = string(runes[0])
			}
		}
		rendered = append(rendered, style.Render(prefix+label))
	}

	separator := t.Muted.Render(" → ")
	row := strings.Join(rendered, separator)

	return lipgloss.PlaceHorizontal(width, lipgloss.Center, row)
}

func stageIndex(s progress.Stage) int {
	for i, stage := range progress.OrderedStages() {
		if stage == s {
			return i
		}
	}
	return -1
}
