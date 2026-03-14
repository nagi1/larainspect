package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/nagi1/larainspect/internal/checks"
	"github.com/nagi1/larainspect/internal/debuglog"
	"github.com/nagi1/larainspect/internal/discovery"
	"github.com/nagi1/larainspect/internal/model"
	"github.com/nagi1/larainspect/internal/orchestrator"
	"github.com/nagi1/larainspect/internal/progress"
	"github.com/nagi1/larainspect/internal/tui"
	"golang.org/x/term"
)

// shouldUseTUI returns true when the TUI is appropriate for the current config
// and environment. Falls back to the line printer for non-TTY, quiet, or
// screen-reader sessions.
func shouldUseTUI(stdin io.Reader, stdout io.Writer, config model.AuditConfig) bool {
	return shouldUseTUIWithTerminalCheck(stdin, stdout, config, func(fd uintptr) bool {
		return term.IsTerminal(int(fd))
	})
}

func shouldUseTUIWithTerminalCheck(stdin io.Reader, stdout io.Writer, config model.AuditConfig, isTerminal func(uintptr) bool) bool {
	if config.ScreenReader || config.Verbosity == model.VerbosityQuiet {
		return false
	}
	if !config.UsesTerminalOutput() || config.ColorMode == model.ColorModeNever {
		return false
	}
	return terminalDescriptorIsTTY(stdin, isTerminal) && terminalDescriptorIsTTY(stdout, isTerminal)
}

func terminalDescriptorIsTTY(stream any, isTerminal func(uintptr) bool) bool {
	descriptor, ok := stream.(interface{ Fd() uintptr })
	if !ok {
		return false
	}

	return isTerminal(descriptor.Fd())
}

// executeAuditWithTUI runs the full audit lifecycle inside the interactive TUI.
// File outputs (JSON/Markdown/SARIF/HTML) are still written if configured.
func executeAuditWithTUI(ctx context.Context, stdin io.Reader, stdout io.Writer, stderr io.Writer, config model.AuditConfig, logger *debuglog.Logger) int {
	auditCtx, cancelAudit := context.WithCancel(ctx)
	defer cancelAudit()

	execution, err := newExecutionContext(config, logger)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return int(model.ExitCodeAuditFailed)
	}

	bus := progress.NewBus()
	defer bus.Close()
	attachDebugLogger(bus, logger)

	app := tui.NewApp(bus, Version)
	program := tea.NewProgram(app, tea.WithAltScreen(), tea.WithInput(stdin), tea.WithOutput(stdout))
	bridge := tui.NewBridge(bus, program)

	outputs, closeOutputs, err := buildTUIOutputs(config)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return int(model.ExitCodeAuditFailed)
	}
	defer closeOutputs()

	orch := orchestrator.Orchestrator{
		Execution:   execution,
		Discovery:   discovery.NewServiceForAudit(execution.Config),
		Checks:      checks.Registered(),
		Outputs:     outputs,
		ProgressBus: bus,
	}

	bridge.Start()

	var auditReport model.Report
	var auditErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		auditReport, auditErr = orch.Run(auditCtx)
		if auditErr == nil {
			program.Send(tui.ReportReadyMsg{Report: auditReport})
		}
	}()

	if _, err := program.Run(); err != nil {
		fmt.Fprintln(stderr, err)
		return int(model.ExitCodeAuditFailed)
	}

	if !app.AuditComplete() {
		cancelAudit()
	}

	wg.Wait()

	if !app.AuditComplete() && errors.Is(auditErr, context.Canceled) {
		return 0
	}
	if auditErr != nil {
		fmt.Fprintln(stderr, auditErr)
		return int(model.ExitCodeAuditFailed)
	}

	runPostProcessing(stderr, config, auditReport)

	return int(model.ExitCodeForReport(auditReport))
}
