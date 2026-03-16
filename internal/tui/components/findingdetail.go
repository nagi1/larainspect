package components

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/nagi1/larainspect/internal/controls"
	"github.com/nagi1/larainspect/internal/model"
	"github.com/nagi1/larainspect/internal/tui/theme"
)

// FindingDetail renders a detailed view of a single finding.
type FindingDetail struct {
	viewport         viewport.Model
	finding          *model.Finding
	theme            *theme.Theme
	width            int
	height           int
	focused          bool
	horizontalOffset int
	contentLines     []string
	statusMessage    string
	statusIsError    bool
}

// NewFindingDetail creates a new finding detail panel.
func NewFindingDetail(t *theme.Theme) *FindingDetail {
	vp := viewport.New(60, 20)
	return &FindingDetail{viewport: vp, theme: t}
}

// SetFinding sets the finding to display.
func (d *FindingDetail) SetFinding(f *model.Finding) {
	d.finding = f
	d.statusMessage = ""
	d.statusIsError = false
	d.rebuildContent()
}

// SetSize updates the panel dimensions.
func (d *FindingDetail) SetSize(w, h int) {
	d.width = w
	d.height = h
	d.viewport.Width = maxInt(1, w-4)
	d.viewport.Height = maxInt(1, h-4)
	d.rebuildContent()
}

// SetFocused updates the focus state for styling and hints.
func (d *FindingDetail) SetFocused(focused bool) {
	d.focused = focused
}

// SetStatus shows a short status line below the navigation hint.
func (d *FindingDetail) SetStatus(message string, isError bool) {
	d.statusMessage = message
	d.statusIsError = isError
}

// HandleKey processes scrolling keys.
func (d *FindingDetail) HandleKey(msg tea.KeyMsg) {
	switch msg.Type {
	case tea.KeyLeft:
		d.shiftHorizontal(-8)
		return
	case tea.KeyRight:
		d.shiftHorizontal(8)
		return
	case tea.KeyHome:
		d.horizontalOffset = 0
		d.refreshViewportContent()
		return
	case tea.KeyEnd:
		d.horizontalOffset = d.maxHorizontalOffset()
		d.refreshViewportContent()
		return
	}

	d.viewport, _ = d.viewport.Update(msg)
}

func (d *FindingDetail) rebuildContent() {
	if d.finding == nil {
		d.contentLines = []string{"  Select a finding to view details."}
		d.horizontalOffset = 0
		d.refreshViewportContent()
		return
	}
	f := d.finding

	contentWidth := d.viewport.Width - 2
	if contentWidth < 20 {
		contentWidth = 20
	}

	lines := []string{
		fmt.Sprintf("  [%s] %s", strings.ToUpper(string(f.Severity)), f.Title),
	}
	lines = append(lines, wrapDetailLine("  ", fmt.Sprintf("Class: %s  |  Confidence: %s  |  Check: %s", f.Class, f.Confidence, f.CheckID), contentWidth)...)
	lines = append(lines, "")

	if f.Why != "" {
		lines = append(lines, "  Why")
		lines = append(lines, wrapDetailLine("    ", f.Why, contentWidth)...)
		lines = append(lines, "")
	}

	if len(f.Evidence) > 0 {
		lines = append(lines, "  Evidence")
		for _, ev := range f.Evidence {
			lines = append(lines, wrapDetailLine("    "+ev.Label+": ", ev.Detail, contentWidth)...)
		}
		lines = append(lines, "")
	}

	if len(f.Affected) > 0 {
		lines = append(lines, "  Affected Targets")
		for _, target := range f.Affected {
			lines = append(lines, wrapDetailLine("    ", formatTargetLine(target), contentWidth)...)
		}
		lines = append(lines, "")
	}

	relatedControls := controls.ForFinding(f.CheckID, f.ID)
	if len(relatedControls) > 0 {
		lines = append(lines, "  Controls")
		for _, control := range relatedControls {
			lines = append(lines, wrapDetailLine("    ", fmt.Sprintf("%s [%s]", control.ID, control.Status), contentWidth)...)
			lines = append(lines, wrapDetailLine("      ", control.Name, contentWidth)...)
		}
		lines = append(lines, "")
	}

	if f.Remediation != "" {
		lines = append(lines, "  Remediation")
		lines = append(lines, wrapDetailLine("    ", f.Remediation, contentWidth)...)
	}

	d.contentLines = lines
	if d.horizontalOffset > d.maxHorizontalOffset() {
		d.horizontalOffset = d.maxHorizontalOffset()
	}
	d.refreshViewportContent()
	d.viewport.GotoTop()
}

// View renders the finding detail panel.
func (d *FindingDetail) View() string {
	border := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(d.theme.Colors.Border).
		Width(d.width).
		Height(d.height)
	if d.focused {
		border = border.BorderForeground(d.theme.Colors.Primary)
	}

	title := d.theme.Subtitle.Render("  Finding Detail")
	hint := d.theme.Muted.Render(d.navigationHint())
	rows := []string{title, hint}
	if d.statusMessage != "" {
		statusStyle := d.theme.SuccessStyle
		if d.statusIsError {
			statusStyle = d.theme.ErrorStyle
		}
		rows = append(rows, statusStyle.Render("  "+d.statusMessage))
	}
	rows = append(rows, "", d.viewport.View())
	content := lipgloss.JoinVertical(lipgloss.Left, rows...)
	return border.Render(content)
}

// PlainText returns the full finding detail in a copy-friendly text format.
func (d *FindingDetail) PlainText() string {
	if d.finding == nil {
		return ""
	}

	f := d.finding
	lines := []string{
		fmt.Sprintf("[%s] %s", strings.ToUpper(string(f.Severity)), f.Title),
		fmt.Sprintf("Class: %s", f.Class),
		fmt.Sprintf("Confidence: %s", f.Confidence),
		fmt.Sprintf("Check: %s", f.CheckID),
	}

	if f.Why != "" {
		lines = append(lines, "", "Why", f.Why)
	}

	if len(f.Evidence) > 0 {
		lines = append(lines, "", "Evidence")
		for _, ev := range f.Evidence {
			lines = append(lines, fmt.Sprintf("- %s: %s", ev.Label, ev.Detail))
		}
	}

	if len(f.Affected) > 0 {
		lines = append(lines, "", "Affected Targets")
		for _, target := range f.Affected {
			lines = append(lines, "- "+formatTargetLine(target))
		}
	}

	relatedControls := controls.ForFinding(f.CheckID, f.ID)
	if len(relatedControls) > 0 {
		lines = append(lines, "", "Controls")
		for _, control := range relatedControls {
			lines = append(lines, fmt.Sprintf("- %s [%s]", control.ID, control.Status))
			lines = append(lines, "  "+control.Name)
		}
	}

	if f.Remediation != "" {
		lines = append(lines, "", "Remediation", f.Remediation)
	}

	return strings.Join(lines, "\n")
}

func wordWrap(text string, width int) string {
	if width <= 0 {
		return text
	}

	return strings.Join(wrapDetailLine("  ", text, width), "\n")
}

func wrapDetailLine(prefix string, text string, width int) []string {
	if width <= 0 {
		return []string{prefix + text}
	}
	words := strings.Fields(text)
	if len(words) == 0 {
		return nil
	}

	var lines []string
	currentLine := prefix
	currentWidth := utf8.RuneCountInString(prefix)
	maxContentWidth := maxInt(8, width-currentWidth)

	for _, word := range words {
		for len(word) > maxContentWidth {
			if utf8.RuneCountInString(currentLine) > currentWidth {
				lines = append(lines, currentLine)
				currentLine = strings.Repeat(" ", currentWidth)
			}
			chunk, rest := splitAtRunes(word, maxContentWidth)
			lines = append(lines, prefix+chunk)
			word = rest
		}

		additionalWidth := utf8.RuneCountInString(word)
		if utf8.RuneCountInString(currentLine) > currentWidth {
			additionalWidth++
		}
		if utf8.RuneCountInString(currentLine)+additionalWidth > width {
			lines = append(lines, currentLine)
			currentLine = strings.Repeat(" ", currentWidth) + word
			continue
		}

		if utf8.RuneCountInString(currentLine) > currentWidth {
			currentLine += " "
		}
		currentLine += word
	}

	if currentLine != "" {
		lines = append(lines, currentLine)
	}

	return lines
}

func formatTargetLine(target model.Target) string {
	parts := []string{fmt.Sprintf("[%s]", target.Type)}
	if target.Name != "" {
		parts = append(parts, target.Name)
	}
	if target.Path != "" {
		parts = append(parts, target.Path)
	}

	return strings.Join(parts, " ")
}

func splitAtRunes(value string, width int) (string, string) {
	if width <= 0 {
		return "", value
	}

	runes := []rune(value)
	if len(runes) <= width {
		return value, ""
	}

	return string(runes[:width]), string(runes[width:])
}

func (d *FindingDetail) shiftHorizontal(delta int) {
	nextOffset := d.horizontalOffset + delta
	switch {
	case nextOffset < 0:
		nextOffset = 0
	case nextOffset > d.maxHorizontalOffset():
		nextOffset = d.maxHorizontalOffset()
	}

	if nextOffset == d.horizontalOffset {
		return
	}

	d.horizontalOffset = nextOffset
	d.refreshViewportContent()
}

func (d *FindingDetail) maxHorizontalOffset() int {
	maxWidth := 0
	for _, line := range d.contentLines {
		if lineWidth := utf8.RuneCountInString(line); lineWidth > maxWidth {
			maxWidth = lineWidth
		}
	}

	return maxInt(0, maxWidth-d.viewport.Width)
}

func (d *FindingDetail) refreshViewportContent() {
	if len(d.contentLines) == 0 {
		d.viewport.SetContent("")
		return
	}

	visibleLines := make([]string, 0, len(d.contentLines))
	for _, line := range d.contentLines {
		visibleLines = append(visibleLines, visibleLine(line, d.horizontalOffset, d.viewport.Width))
	}

	d.viewport.SetContent(strings.Join(visibleLines, "\n"))
}

func (d *FindingDetail) navigationHint() string {
	if maxOffset := d.maxHorizontalOffset(); maxOffset > 0 {
		return fmt.Sprintf("  Scroll: ↑↓  Pan: ←→ (%d/%d)  Home/End  C/Y: copy  Tab: switch panel", d.horizontalOffset, maxOffset)
	}

	return "  Scroll: ↑↓  Pan: none  C/Y: copy  Tab: switch panel"
}

func visibleLine(line string, offset int, width int) string {
	if width <= 0 {
		return ""
	}

	runes := []rune(line)
	if offset >= len(runes) {
		return ""
	}

	end := offset + width
	if end > len(runes) {
		end = len(runes)
	}

	return string(runes[offset:end])
}

func maxInt(left int, right int) int {
	if left > right {
		return left
	}

	return right
}
