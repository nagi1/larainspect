package components

import (
	"fmt"

	"github.com/charmbracelet/lipgloss"
	"github.com/nagi1/larainspect/internal/tui/banner"
	"github.com/nagi1/larainspect/internal/tui/theme"
)

// HeaderData holds the information displayed in the header bar.
type HeaderData struct {
	AppName        string
	AppPath        string
	LaravelVersion string
	PHPVersion     string
	PackageCount   int
	ToolVersion    string
	AuditRunning   bool
	AuditComplete  bool
	AuditError     bool
}

// RenderHeader renders the top header bar across the full width.
func RenderHeader(data HeaderData, t *theme.Theme, width int) string {
	logo := " " + banner.RenderCompact() + " "

	sep := t.HeaderBar.Render(
		lipgloss.NewStyle().
			Foreground(lipgloss.AdaptiveColor{Light: "#BDBDBD", Dark: "#616161"}).
			Render(" | "),
	)

	version := t.HeaderBar.Render(fmt.Sprintf("v%s", data.ToolVersion))

	var status string
	statusBg := lipgloss.NewStyle().Padding(0, 1).Bold(true).
		Foreground(lipgloss.AdaptiveColor{Light: "#FFFFFF", Dark: "#FFFFFF"})

	switch {
	case data.AuditError:
		status = statusBg.Background(t.Colors.Error).Render("ERROR")
	case data.AuditComplete:
		status = statusBg.Background(t.Colors.Success).Render("COMPLETE")
	case data.AuditRunning:
		status = statusBg.Background(t.Colors.StageActive).Render("AUDITING…")
	default:
		status = t.Muted.Render("READY")
	}

	rightWidth := lipgloss.Width(status)

	// Build metadata parts, then decide how many fit.
	type metaPart struct {
		text string
		w    int
	}
	var allParts []metaPart

	if data.AppName != "" {
		r := t.HeaderBar.Render(fmt.Sprintf("App: %s", data.AppName))
		allParts = append(allParts, metaPart{r, lipgloss.Width(r)})
	} else if data.AppPath != "" {
		r := t.HeaderBar.Render(fmt.Sprintf("Path: %s", data.AppPath))
		allParts = append(allParts, metaPart{r, lipgloss.Width(r)})
	}
	if data.LaravelVersion != "" {
		r := t.HeaderBar.Render(fmt.Sprintf("Laravel %s", data.LaravelVersion))
		allParts = append(allParts, metaPart{r, lipgloss.Width(r)})
	}
	if data.PHPVersion != "" {
		r := t.HeaderBar.Render(fmt.Sprintf("PHP %s", data.PHPVersion))
		allParts = append(allParts, metaPart{r, lipgloss.Width(r)})
	}
	if data.PackageCount > 0 {
		label := "packages"
		if data.PackageCount == 1 {
			label = "package"
		}
		r := t.HeaderBar.Render(fmt.Sprintf("%d %s", data.PackageCount, label))
		allParts = append(allParts, metaPart{r, lipgloss.Width(r)})
	}

	sepW := lipgloss.Width(sep)
	logoW := lipgloss.Width(logo)
	versionW := lipgloss.Width(version)

	// Progressively include metadata until it doesn't fit.
	budget := width - logoW - versionW - rightWidth - sepW*2 - 2
	leftParts := []string{logo}
	for _, part := range allParts {
		needed := sepW + part.w
		if budget >= needed {
			leftParts = append(leftParts, sep, part.text)
			budget -= needed
		}
	}
	leftParts = append(leftParts, sep, version)

	left := lipgloss.JoinHorizontal(lipgloss.Center, leftParts...)
	leftWidth := lipgloss.Width(left)

	gap := width - leftWidth - rightWidth
	if gap < 0 {
		gap = 1
	}

	padding := fmt.Sprintf("%*s", gap, "")

	bar := t.HeaderBar.Width(width).Render(
		lipgloss.JoinHorizontal(lipgloss.Center, left, padding, status),
	)

	return bar
}
