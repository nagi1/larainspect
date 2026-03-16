package views

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/nagi1/larainspect/internal/model"
	"github.com/nagi1/larainspect/internal/tui/components"
	"github.com/nagi1/larainspect/internal/tui/theme"
)

// SortColumn determines the sort field for findings.
type SortColumn int

const (
	SortBySeverity SortColumn = iota
	SortByClass
	SortByCheckID
)

func (s SortColumn) String() string {
	switch s {
	case SortBySeverity:
		return "Severity"
	case SortByClass:
		return "Class"
	case SortByCheckID:
		return "Check ID"
	default:
		return "Unknown"
	}
}

// ResultsData holds the post-audit report data for display.
type ResultsData struct {
	Findings []model.Finding
	Unknowns []model.Unknown
	Summary  model.Summary
	Duration time.Duration
	AppName  string
	AppPath  string
}

// ResultsView renders the post-audit results screen.
type ResultsView struct {
	theme *theme.Theme
	data  ResultsData

	// Table
	table    table.Model
	findings []model.Finding

	// Sort
	sortColumn    SortColumn
	sortAscending bool

	// Detail panel
	detail *components.FindingDetail

	// Layout
	width            int
	height           int
	focusPanel       int // 0 = table, 1 = detail
	horizontalOffset int

	// Key bindings (local)
	tabKey  key.Binding
	sortKey key.Binding
}

// NewResultsView creates a new results view from audit data.
func NewResultsView(t *theme.Theme, data ResultsData) *ResultsView {
	v := &ResultsView{
		theme:    t,
		data:     data,
		findings: make([]model.Finding, len(data.Findings)),
		detail:   components.NewFindingDetail(t),
		tabKey: key.NewBinding(
			key.WithKeys("tab"),
		),
		sortKey: key.NewBinding(
			key.WithKeys("s"),
		),
	}
	copy(v.findings, data.Findings)
	v.sortFindings()
	v.buildTable()
	v.syncPanelFocus()

	if len(v.findings) > 0 {
		v.detail.SetFinding(&v.findings[0])
	}

	return v
}

// SetSize updates dimensions and propagates to sub-components.
func (v *ResultsView) SetSize(w, h int) {
	v.width = w
	v.height = h

	bodyH := v.bodyHeight()
	cursor := v.table.Cursor()
	v.buildTable()
	if cursor >= 0 && cursor < len(v.findings) {
		v.table.SetCursor(cursor)
	}

	tableRatio := v.tableRatio()
	tableW := int(float64(w) * tableRatio)
	detailW := w - tableW - 3
	if detailW < 24 {
		detailW = 24
		tableW = maxInt(24, w-detailW-3)
	}

	v.table.SetWidth(tableW)
	v.table.SetHeight(bodyH - 2)
	if v.horizontalOffset > v.maxTableHorizontalOffset() {
		v.horizontalOffset = v.maxTableHorizontalOffset()
	}
	v.syncPanelFocus()
	v.detail.SetSize(detailW, bodyH)
}

// tableRatio returns the table panel width ratio based on terminal width.
func (v *ResultsView) tableRatio() float64 {
	if v.focusPanel == 1 {
		switch {
		case v.width >= 160:
			return 0.34
		case v.width >= 100:
			return 0.42
		default:
			return 0.48
		}
	}

	switch {
	case v.width >= 160:
		return 0.40
	case v.width >= 100:
		return 0.50
	default:
		return 0.55
	}
}

func (v *ResultsView) buildTable() {
	columns := v.adaptiveColumns()
	rows := v.tableRows(columns)

	t := table.New(
		table.WithColumns(columns),
		table.WithRows(rows),
		table.WithFocused(true),
		table.WithHeight(20),
	)

	s := table.DefaultStyles()
	s.Header = v.theme.TableHeader
	s.Selected = v.theme.TableSelected
	t.SetStyles(s)

	v.table = t
}

func (v *ResultsView) tableRows(columns []table.Column) []table.Row {
	rows := make([]table.Row, 0, len(v.findings))
	for _, f := range v.findings {
		rows = append(rows, table.Row{
			theme.SeverityLabel(f.Severity),
			classLabel(f.Class),
			string(f.Confidence),
			f.Title,
			f.CheckID,
		})
	}

	return rows
}

// adaptiveColumns returns table columns scaled to the current width.
func (v *ResultsView) adaptiveColumns() []table.Column {
	tableRatio := v.tableRatio()
	availW := int(float64(v.width)*tableRatio) - 6
	if availW < 40 {
		availW = 40
	}

	sevW := ansi.StringWidth("Severity")
	classW := ansi.StringWidth("Class")
	confW := ansi.StringWidth("Confidence")
	titleW := ansi.StringWidth("Title")
	checkW := ansi.StringWidth("Check ID")

	for _, finding := range v.findings {
		sevW = maxInt(sevW, ansi.StringWidth(theme.SeverityLabel(finding.Severity)))
		classW = maxInt(classW, ansi.StringWidth(classLabel(finding.Class)))
		confW = maxInt(confW, ansi.StringWidth(string(finding.Confidence)))
		titleW = maxInt(titleW, ansi.StringWidth(finding.Title))
		checkW = maxInt(checkW, ansi.StringWidth(finding.CheckID))
	}

	sevW = maxInt(sevW, 8)
	classW = maxInt(classW, 10)
	confW = maxInt(confW, 10)
	titleW = maxInt(titleW, 12)
	checkW = maxInt(checkW, 16)
	titleW = maxInt(titleW, availW-sevW-classW-confW-checkW)

	return []table.Column{
		{Title: "Severity", Width: sevW},
		{Title: "Class", Width: classW},
		{Title: "Confidence", Width: confW},
		{Title: "Title", Width: titleW},
		{Title: "Check ID", Width: checkW},
	}
}

func (v *ResultsView) sortFindings() {
	sort.SliceStable(v.findings, func(i, j int) bool {
		switch v.sortColumn {
		case SortBySeverity:
			if v.sortAscending {
				return v.findings[i].Severity.Weight() < v.findings[j].Severity.Weight()
			}
			return v.findings[i].Severity.Weight() > v.findings[j].Severity.Weight()
		case SortByClass:
			if v.sortAscending {
				return v.findings[i].Class < v.findings[j].Class
			}
			return v.findings[i].Class > v.findings[j].Class
		case SortByCheckID:
			if v.sortAscending {
				return v.findings[i].CheckID < v.findings[j].CheckID
			}
			return v.findings[i].CheckID > v.findings[j].CheckID
		}
		return false
	})
}

// HandleKey routes key events for table navigation, sorting, and detail scrolling.
func (v *ResultsView) HandleKey(msg tea.KeyMsg) tea.Cmd {
	switch {
	case key.Matches(msg, v.tabKey):
		v.focusPanel = (v.focusPanel + 1) % 2
		v.syncPanelFocus()
		if v.width > 0 && v.height > 0 {
			v.SetSize(v.width, v.height)
		}
		return nil
	case key.Matches(msg, v.sortKey):
		prevCol := v.sortColumn
		v.sortColumn = (v.sortColumn + 1) % 3
		if v.sortColumn == prevCol {
			v.sortAscending = !v.sortAscending
		} else {
			v.sortAscending = false
		}
		cursor := v.table.Cursor()
		v.sortFindings()
		v.buildTable()
		if cursor >= 0 && cursor < len(v.findings) {
			v.table.SetCursor(cursor)
		}
		if v.width > 0 && v.height > 0 {
			v.SetSize(v.width, v.height)
		}
		v.syncPanelFocus()
		return nil
	}

	if v.focusPanel == 0 {
		switch msg.Type {
		case tea.KeyLeft:
			v.shiftTableHorizontal(-8)
			return nil
		case tea.KeyRight:
			v.shiftTableHorizontal(8)
			return nil
		case tea.KeyHome:
			v.horizontalOffset = 0
			return nil
		case tea.KeyEnd:
			v.horizontalOffset = v.maxTableHorizontalOffset()
			return nil
		}

		var cmd tea.Cmd
		v.table, cmd = v.table.Update(msg)
		idx := v.table.Cursor()
		if idx >= 0 && idx < len(v.findings) {
			v.detail.SetFinding(&v.findings[idx])
		}
		return cmd
	}

	v.detail.HandleKey(msg)
	return nil
}

// View renders the complete results view.
func (v *ResultsView) View(width, height int) string {
	if width == 0 || height == 0 {
		return ""
	}

	summary := v.renderSummary(width)
	sep := components.RenderSeparator(v.theme, width)

	sortDir := "↓"
	if v.sortAscending {
		sortDir = "↑"
	}
	panHint := "←→ pan focused  |  Home/End"
	if v.focusPanel == 0 {
		if maxOffset := v.maxTableHorizontalOffset(); maxOffset > 0 {
			panHint = fmt.Sprintf("←→ pan findings (%d/%d)  |  Home/End", v.horizontalOffset, maxOffset)
		} else {
			panHint = "←→ pan findings: none"
		}
	}
	sortInfo := v.theme.Muted.Render(fmt.Sprintf("  Sorted by: %s %s  |  Focus: %s  |  Tab switch  |  S sort  |  ↑↓ navigate  |  %s",
		v.sortColumn.String(), sortDir, panelName(v.focusPanel), panHint))

	tableView := v.renderTable()
	detailView := v.detail.View()
	body := lipgloss.JoinHorizontal(lipgloss.Top, tableView, " ", detailView)

	parts := []string{summary, sep, sortInfo, body}

	// Show unknowns summary when present.
	if len(v.data.Unknowns) > 0 {
		unknownsRow := v.renderUnknownsSummary(width)
		// Insert unknowns row after summary, before separator.
		parts = []string{summary, unknownsRow, sep, sortInfo, body}
	}

	return lipgloss.JoinVertical(lipgloss.Left, parts...)
}

func (v *ResultsView) renderSummary(width int) string {
	total := v.data.Summary.TotalFindings
	unknowns := v.data.Summary.Unknowns

	header := v.theme.Title.Render(fmt.Sprintf("  Audit Complete — %d findings, %d unknowns in %s",
		total, unknowns, v.data.Duration.Round(time.Millisecond)))

	var infoParts []string
	if v.data.AppName != "" {
		infoParts = append(infoParts, v.data.AppName)
	} else if v.data.AppPath != "" {
		infoParts = append(infoParts, v.data.AppPath)
	}
	infoParts = append(infoParts,
		fmt.Sprintf("%d direct", v.data.Summary.DirectFindings),
		fmt.Sprintf("%d heuristic", v.data.Summary.HeuristicFindings),
		fmt.Sprintf("%d compromise", v.data.Summary.CompromiseIndicators),
	)

	sep := v.theme.Muted.Render(" · ")
	var styledParts []string
	for _, p := range infoParts {
		styledParts = append(styledParts, v.theme.AccentStyle.Render(p))
	}
	infoLine := lipgloss.JoinHorizontal(lipgloss.Center, interleave(styledParts, sep)...)

	stats := components.RenderLiveStats(v.data.Summary.SeverityCounts, v.theme, width)

	return lipgloss.JoinVertical(lipgloss.Left,
		lipgloss.PlaceHorizontal(width, lipgloss.Center, header),
		lipgloss.PlaceHorizontal(width, lipgloss.Center, infoLine),
		"",
		stats,
	)
}

// renderUnknownsSummary renders a compact unknowns section when unknowns exist.
func (v *ResultsView) renderUnknownsSummary(width int) string {
	count := len(v.data.Unknowns)
	header := v.theme.WarningStyle.Render(
		fmt.Sprintf("  ⚠ %d unknowns — items that could not be fully evaluated", count))

	var lines []string
	lines = append(lines, lipgloss.PlaceHorizontal(width, lipgloss.Center, header))

	// Show up to 5 unknown titles as a preview.
	limit := 5
	if len(v.data.Unknowns) < limit {
		limit = len(v.data.Unknowns)
	}
	for i := 0; i < limit; i++ {
		u := v.data.Unknowns[i]
		title := truncate(u.Title, width-12)
		line := v.theme.Muted.Render(fmt.Sprintf("    ? %s", title))
		lines = append(lines, line)
	}
	if len(v.data.Unknowns) > 5 {
		more := v.theme.Muted.Render(fmt.Sprintf("    … and %d more", len(v.data.Unknowns)-5))
		lines = append(lines, more)
	}

	return lipgloss.JoinVertical(lipgloss.Left, lines...)
}

func interleave(items []string, sep string) []string {
	if len(items) == 0 {
		return nil
	}
	result := make([]string, 0, len(items)*2-1)
	for i, item := range items {
		if i > 0 {
			result = append(result, sep)
		}
		result = append(result, item)
	}
	return result
}

func (v *ResultsView) renderTable() string {
	border := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(v.theme.Colors.Border).
		Width(v.table.Width()).
		Height(v.bodyHeight())

	if v.focusPanel == 0 {
		border = border.BorderForeground(v.theme.Colors.Primary)
	}

	contentWidth := maxInt(1, v.table.Width()-2)
	renderedLines := strings.Split(v.table.View(), "\n")
	visibleLines := make([]string, 0, len(renderedLines))
	for _, line := range renderedLines {
		visibleLines = append(visibleLines, ansi.Cut(line, v.horizontalOffset, v.horizontalOffset+contentWidth))
	}

	return border.Render(strings.Join(visibleLines, "\n"))
}

func panelName(idx int) string {
	if idx == 0 {
		return "Findings"
	}
	return "Detail"
}

func (v *ResultsView) bodyHeight() int {
	bodyH := v.height - 6
	if bodyH < 6 {
		return 6
	}

	return bodyH
}

func (v *ResultsView) syncPanelFocus() {
	if v.focusPanel == 0 {
		v.table.Focus()
		v.detail.SetFocused(false)
		return
	}

	v.table.Blur()
	v.detail.SetFocused(true)
}

func (v *ResultsView) shiftTableHorizontal(delta int) {
	nextOffset := v.horizontalOffset + delta
	switch {
	case nextOffset < 0:
		nextOffset = 0
	case nextOffset > v.maxTableHorizontalOffset():
		nextOffset = v.maxTableHorizontalOffset()
	}

	if nextOffset == v.horizontalOffset {
		return
	}

	v.horizontalOffset = nextOffset
}

func (v *ResultsView) maxTableHorizontalOffset() int {
	visibleWidth := maxInt(1, v.table.Width()-2)
	maxWidth := 0
	for _, line := range strings.Split(v.table.View(), "\n") {
		maxWidth = maxInt(maxWidth, ansi.StringWidth(line))
	}

	return maxInt(0, maxWidth-visibleWidth)
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	return s[:max-2] + ".."
}

func classLabel(class model.FindingClass) string {
	switch class {
	case model.FindingClassDirect:
		return "Direct"
	case model.FindingClassHeuristic:
		return "Heuristic"
	case model.FindingClassCompromiseIndicator:
		return "Indicator"
	default:
		return string(class)
	}
}

func maxInt(left int, right int) int {
	if left > right {
		return left
	}

	return right
}
