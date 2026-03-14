package components

import (
	"strings"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/lipgloss"
	"github.com/nagi1/larainspect/internal/tui/theme"
)

// RenderFooter renders the bottom help bar.
func RenderFooter(helpModel help.Model, keys help.KeyMap, t *theme.Theme, width int) string {
	helpView := helpModel.View(keys)
	return t.FooterBar.Width(width).Render(helpView)
}

// RenderSeparator renders a horizontal line separator.
func RenderSeparator(t *theme.Theme, width int) string {
	return lipgloss.NewStyle().
		Foreground(t.Colors.Border).
		Render(strings.Repeat("─", width))
}
