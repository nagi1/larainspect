package tui

import (
	"time"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/nagi1/larainspect/internal/model"
	"github.com/nagi1/larainspect/internal/progress"
	"github.com/nagi1/larainspect/internal/tui/components"
	"github.com/nagi1/larainspect/internal/tui/theme"
	"github.com/nagi1/larainspect/internal/tui/views"
)

// App is the root Bubble Tea model for Larainspect.
type App struct {
	bus     *progress.Bus
	state   *progress.State
	version string

	// Layout
	width  int
	height int
	ready  bool

	// View state
	activeView ViewID

	// Theme and help
	theme   *theme.Theme
	keys    KeyMap
	help    help.Model
	spinner spinner.Model

	// Audit lifecycle (not tracked by progress.State)
	report        *model.Report
	auditRunning  bool
	auditComplete bool
	auditError    error

	// Sub-views
	scanView    *views.ScanView
	resultsView *views.ResultsView
}

// NewApp creates the root TUI model.
func NewApp(bus *progress.Bus, version string) *App {
	t := theme.DefaultTheme()

	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(t.Colors.StageActive)

	h := help.New()
	h.ShowAll = false

	return &App{
		bus:        bus,
		state:      progress.NewState(200),
		version:    version,
		theme:      t,
		keys:       DefaultKeyMap(),
		help:       h,
		spinner:    s,
		activeView: ViewScan,
		scanView:   views.NewScanView(t),
	}
}

// Init returns the initial commands.
func (a *App) Init() tea.Cmd {
	return tea.Batch(
		a.spinner.Tick,
		tickCmd(),
	)
}

// Update handles all incoming messages.
func (a *App) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		a.width = msg.Width
		a.height = msg.Height
		a.ready = true
		a.propagateSize()
		return a, nil

	case tea.KeyMsg:
		switch {
		case key.Matches(msg, a.keys.Quit):
			return a, tea.Quit
		case key.Matches(msg, a.keys.Help):
			a.help.ShowAll = !a.help.ShowAll
			return a, nil
		case key.Matches(msg, a.keys.Tab):
			return a, a.handleTabKey(msg)
		case key.Matches(msg, a.keys.Escape):
			if a.activeView == ViewResults {
				a.activeView = ViewScan
				return a, nil
			}
			return a, nil
		}

		cmd := a.delegateKeyToView(msg)
		cmds = append(cmds, cmd)

	case BusEventMsg:
		cmd := a.handleBusEvent(msg.Event)
		cmds = append(cmds, cmd)

	case tickMsg:
		if a.activeView == ViewScan {
			cmd := a.scanView.Tick(msg)
			cmds = append(cmds, cmd)
		}
		cmds = append(cmds, tickCmd())

	case spinner.TickMsg:
		var cmd tea.Cmd
		a.spinner, cmd = a.spinner.Update(msg)
		cmds = append(cmds, cmd)

	case ReportReadyMsg:
		cmd := a.setReport(msg.Report)
		cmds = append(cmds, cmd)

	case switchViewMsg:
		a.activeView = msg.view
	}

	return a, tea.Batch(cmds...)
}

// View renders the entire screen.
func (a *App) View() string {
	if !a.ready {
		return "\n  Starting Larainspect…"
	}

	header := a.renderHeader()
	footer := a.renderFooter()
	contentH := a.contentHeight(header, footer)

	var content string
	switch a.activeView {
	case ViewScan:
		content = a.scanView.View(a.width, contentH)
	case ViewResults:
		if a.resultsView != nil {
			content = a.resultsView.View(a.width, contentH)
		} else {
			content = a.theme.Muted.Render("\n  Audit still in progress — results will appear when complete.")
		}
	}

	return lipgloss.JoinVertical(lipgloss.Left, header, content, footer)
}

// SetReport provides the final report for use in the results view.
func (a *App) SetReport(report model.Report) {
	_ = a.setReport(report)
}

// AuditComplete reports whether the interactive audit reached completion.
func (a *App) AuditComplete() bool {
	return a.auditComplete
}

func (a *App) handleBusEvent(event progress.Event) tea.Cmd {
	// Delegate all state tracking to the shared progress.State.
	a.state.Handle(event)

	// Handle audit lifecycle events that need TUI-specific behavior.
	switch event.Type {
	case progress.EventAuditStarted:
		a.auditRunning = true

	case progress.EventAuditCompleted:
		return a.handleAuditCompleted()

	case progress.EventAuditFailed:
		a.auditRunning = false
		a.auditError = event.Err
	}

	// Push the latest snapshot to the scan view.
	a.scanView.UpdateFromSnapshot(a.state.Snapshot())
	return nil
}

func (a *App) handleAuditCompleted() tea.Cmd {
	a.auditRunning = false
	a.auditComplete = true
	a.scanView.SetAuditComplete(true)

	if a.initResultsView() {
		return switchViewCmd(ViewResults)
	}

	return nil
}

func (a *App) handleTabKey(msg tea.KeyMsg) tea.Cmd {
	if a.auditComplete && a.activeView == ViewScan {
		a.activeView = ViewResults
		return nil
	}
	if a.activeView == ViewResults && a.resultsView != nil {
		return a.resultsView.HandleKey(msg)
	}
	return nil
}

func (a *App) setReport(report model.Report) tea.Cmd {
	a.report = &report

	if a.auditComplete && a.initResultsView() && a.activeView == ViewScan {
		return switchViewCmd(ViewResults)
	}

	return nil
}

func (a *App) initResultsView() bool {
	if a.report == nil {
		return false
	}

	snap := a.state.Snapshot()
	dur, _ := time.ParseDuration(a.report.Duration)
	a.resultsView = views.NewResultsView(a.theme, views.ResultsData{
		Findings: a.report.Findings(),
		Unknowns: a.report.Unknowns,
		Summary:  a.report.Summary,
		Duration: dur,
		AppName:  snap.Context.AppName,
		AppPath:  snap.Context.AppPath,
	})
	a.propagateSize()

	return true
}

func (a *App) propagateSize() {
	header := a.renderHeader()
	footer := a.renderFooter()
	contentH := a.contentHeight(header, footer)

	a.scanView.SetSize(a.width, contentH)
	if a.resultsView != nil {
		a.resultsView.SetSize(a.width, contentH)
	}
	a.help.Width = a.width
}

func (a *App) contentHeight(header, footer string) int {
	h := a.height - lipgloss.Height(header) - lipgloss.Height(footer)
	if h < 4 {
		return 4
	}
	return h
}

func (a *App) delegateKeyToView(msg tea.KeyMsg) tea.Cmd {
	switch a.activeView {
	case ViewScan:
		a.scanView.HandleKey(msg)
		return nil
	case ViewResults:
		if a.resultsView != nil {
			return a.resultsView.HandleKey(msg)
		}
	}
	return nil
}

func (a *App) renderHeader() string {
	snap := a.state.Snapshot()
	data := components.HeaderData{
		AppName:        snap.Context.AppName,
		AppPath:        snap.Context.AppPath,
		LaravelVersion: snap.Context.LaravelVersion,
		PHPVersion:     snap.Context.PHPVersion,
		PackageCount:   snap.Context.PackageCount,
		ToolVersion:    a.version,
		AuditRunning:   a.auditRunning,
		AuditComplete:  a.auditComplete,
		AuditError:     a.auditError != nil,
	}
	return components.RenderHeader(data, a.theme, a.width)
}

func (a *App) renderFooter() string {
	return components.RenderFooter(a.help, a.keys, a.theme, a.width)
}

func tickCmd() tea.Cmd {
	return tea.Tick(100*time.Millisecond, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

func switchViewCmd(v ViewID) tea.Cmd {
	return func() tea.Msg { return switchViewMsg{view: v} }
}
