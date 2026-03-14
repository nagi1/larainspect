package views

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/nagi1/larainspect/internal/model"
	"github.com/nagi1/larainspect/internal/progress"
	"github.com/nagi1/larainspect/internal/tui/components"
	"github.com/nagi1/larainspect/internal/tui/theme"
)

// ScanView renders the audit-in-progress screen.
type ScanView struct {
	theme *theme.Theme

	// Sub-components
	currentStage  progress.Stage
	checkPanel    *components.CheckPanel
	eventLog      *components.EventLog
	auditComplete bool

	// Data from snapshot
	severityCounts map[model.Severity]int
	unknownCount   int
	checkCompleted int
	checkTotal     int
	corrCompleted  int
	corrTotal      int
	appName        string
	appPath        string
	laravelVersion string
	phpVersion     string
	packageCount   int
	lastEvent      progress.Event
	tickCount      int

	// Layout
	width  int
	height int
}

// NewScanView creates a new scan view.
func NewScanView(t *theme.Theme) *ScanView {
	return &ScanView{
		theme:          t,
		checkPanel:     components.NewCheckPanel(t),
		eventLog:       components.NewEventLog(t),
		severityCounts: make(map[model.Severity]int),
	}
}

// SetSize updates dimensions and propagates to sub-components.
func (v *ScanView) SetSize(w, h int) {
	v.width = w
	v.height = h

	overhead := 4
	if v.appName != "" || v.laravelVersion != "" {
		overhead += 2
	}
	bodyH := h - overhead
	if bodyH < 4 {
		bodyH = 4
	}

	// Responsive split: stack vertically on narrow terminals.
	if w < 70 {
		v.checkPanel.SetSize(w-2, bodyH/2)
		v.eventLog.SetSize(w-2, bodyH/2)
	} else {
		checkW := int(float64(w) * 0.30)
		logW := w - checkW - 3
		v.checkPanel.SetSize(checkW, bodyH)
		v.eventLog.SetSize(logW, bodyH)
	}
}

// UpdateFromSnapshot applies a progress.Snapshot to the scan view in one call.
func (v *ScanView) UpdateFromSnapshot(snap progress.Snapshot) {
	v.currentStage = snap.CurrentStage
	v.severityCounts = snap.SeverityCounts
	v.unknownCount = snap.UnknownsObserved
	v.checkCompleted = snap.CheckCompleted
	v.checkTotal = snap.CheckTotal
	v.corrCompleted = snap.CorrelatorCompleted
	v.corrTotal = snap.CorrelatorTotal

	// Merge checks and correlators for the component panel.
	allComponents := make([]progress.ComponentState, 0, len(snap.Checks)+len(snap.Correlators))
	allComponents = append(allComponents, snap.Checks...)
	allComponents = append(allComponents, snap.Correlators...)
	v.checkPanel.SetChecks(allComponents)

	// Update app info from context.
	ctx := snap.Context
	if ctx.AppName != "" {
		v.appName = ctx.AppName
	}
	if ctx.AppPath != "" {
		v.appPath = ctx.AppPath
	}
	v.laravelVersion = ctx.LaravelVersion
	v.phpVersion = ctx.PHPVersion
	v.packageCount = ctx.PackageCount

	if len(snap.RecentEvents) > 0 {
		v.lastEvent = snap.RecentEvents[len(snap.RecentEvents)-1]
	}
	v.eventLog.SetEvents(snap.RecentEvents)
}

// SetAuditComplete marks the audit as complete for stage rendering.
func (v *ScanView) SetAuditComplete(complete bool) {
	v.auditComplete = complete
}

// Tick forwards tick to check panel for spinner animation.
func (v *ScanView) Tick(msg tea.Msg) tea.Cmd {
	v.tickCount++
	return v.checkPanel.Tick(msg)
}

// HandleKey delegates scrolling to event log.
func (v *ScanView) HandleKey(msg tea.KeyMsg) {
	v.eventLog.HandleKey(msg)
}

// View renders the complete scan view.
func (v *ScanView) View(width, height int) string {
	if width == 0 || height == 0 {
		return ""
	}

	// 1. Pipeline stage progress
	stageRow := components.RenderStageProgress(v.currentStage, v.auditComplete, v.theme, width)

	// 2. Separator
	sep := components.RenderSeparator(v.theme, width)

	// 3. App info bar (only shown once resolved)
	infoRow := v.renderAppInfo(width)

	// 4. Live stats (severity + unknowns)
	statsRow := components.RenderLiveStats(v.severityCounts, v.theme, width)
	if v.unknownCount > 0 {
		unknownBadge := v.theme.WarningStyle.Render(fmt.Sprintf(" %d inconclusive ", v.unknownCount))
		statsRow = lipgloss.JoinHorizontal(lipgloss.Center, statsRow, "  ", unknownBadge)
		statsRow = lipgloss.PlaceHorizontal(width, lipgloss.Center, statsRow)
	}

	// 5. Completed / failed state banner
	statusRow := v.renderStatusBanner(width)

	// 6. Body: check panel (left) + event log (right)
	var body string
	if width < 70 {
		body = lipgloss.JoinVertical(lipgloss.Left, v.checkPanel.View(), "", v.eventLog.View())
	} else {
		body = lipgloss.JoinHorizontal(lipgloss.Top, v.checkPanel.View(), " ", v.eventLog.View())
	}

	rows := []string{stageRow, sep}
	if infoRow != "" {
		rows = append(rows, infoRow, sep)
	}
	rows = append(rows, statsRow, sep)
	if statusRow != "" {
		rows = append(rows, statusRow, sep)
	}
	rows = append(rows, body)

	return lipgloss.JoinVertical(lipgloss.Left, rows...)
}

func (v *ScanView) renderAppInfo(width int) string {
	if v.appName == "" && v.laravelVersion == "" && v.appPath == "" {
		return ""
	}

	var parts []string
	if v.appName != "" {
		parts = append(parts, v.theme.Bold.Render(v.appName))
	} else if v.appPath != "" {
		parts = append(parts, v.theme.Bold.Render(v.appPath))
	}
	if v.laravelVersion != "" {
		parts = append(parts, v.theme.AccentStyle.Render(fmt.Sprintf("Laravel %s", v.laravelVersion)))
	}
	if v.phpVersion != "" {
		parts = append(parts, v.theme.AccentStyle.Render(fmt.Sprintf("PHP %s", v.phpVersion)))
	}
	if v.packageCount > 0 {
		label := "packages"
		if v.packageCount == 1 {
			label = "package"
		}
		parts = append(parts, v.theme.Muted.Render(fmt.Sprintf("%d %s", v.packageCount, label)))
	}

	row := strings.Join(parts, v.theme.Muted.Render("  ·  "))
	return lipgloss.PlaceHorizontal(width, lipgloss.Center, row)
}

func (v *ScanView) renderStatusBanner(width int) string {
	if v.auditComplete {
		total := 0
		for _, c := range v.severityCounts {
			total += c
		}

		msg := fmt.Sprintf("Audit complete — %d findings, %d unknowns",
			total, v.unknownCount)
		hint := "  [Tab] View Results"
		styled := v.theme.SuccessStyle.Render("  ✓ "+msg) + v.theme.Muted.Render(hint)
		return lipgloss.PlaceHorizontal(width, lipgloss.Center, styled)
	}

	spinnerFrames := []string{"|", "/", "-", `\`}
	frame := spinnerFrames[v.tickCount%len(spinnerFrames)]
	stageLabel := "Starting"
	if v.currentStage != "" {
		stageLabel = v.currentStage.Label()
	}

	detail := v.liveStatusDetail()
	message := fmt.Sprintf("  %s Working: %s", frame, stageLabel)
	if detail != "" {
		message += " — " + detail
	}

	return lipgloss.PlaceHorizontal(width, lipgloss.Center, v.theme.AccentStyle.Render(message))
}

func (v *ScanView) liveStatusDetail() string {
	switch v.currentStage {
	case progress.StageChecks:
		if v.checkTotal > 0 {
			return fmt.Sprintf("%d/%d checks complete", v.checkCompleted, v.checkTotal)
		}
	case progress.StageCorrelation:
		if v.corrTotal > 0 {
			return fmt.Sprintf("%d/%d correlators complete", v.corrCompleted, v.corrTotal)
		}
	case progress.StageDiscovery:
		if v.appPath != "" {
			return fmt.Sprintf("scanning %s", v.appPath)
		}
	}

	if v.lastEvent.Message != "" {
		return v.lastEvent.Message
	}

	switch v.currentStage {
	case progress.StageDiscovery:
		return "collecting host and Laravel evidence"
	case progress.StageChecks:
		return "loading and running registered checks"
	case progress.StageCorrelation:
		return "linking related findings"
	case progress.StagePostProcess:
		return "applying baseline and history rules"
	case progress.StageReport:
		return "building the final report"
	default:
		return "preparing audit execution"
	}
}
