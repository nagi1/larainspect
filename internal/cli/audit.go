package cli

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/nagi1/larainspect/internal/checks"
	"github.com/nagi1/larainspect/internal/discovery"
	"github.com/nagi1/larainspect/internal/model"
	"github.com/nagi1/larainspect/internal/orchestrator"
	"github.com/nagi1/larainspect/internal/runner"
	"github.com/nagi1/larainspect/internal/ux"
	"github.com/spf13/cobra"
)

func runAuditCommand(ctx context.Context, stdout io.Writer, stderr io.Writer, args []string) int {
	return runAuditCommandWithInput(ctx, strings.NewReader(""), stdout, stderr, args)
}

func runAuditCommandWithInput(ctx context.Context, stdin io.Reader, stdout io.Writer, stderr io.Writer, args []string) int {
	config, helpRequested, err := parseAuditConfig(args)
	if helpRequested {
		printAuditHelp(stdout)
		return 0
	}
	if err != nil {
		newUsageError(err, printAuditHelp).write(stderr)
		return int(model.ExitCodeUsageError)
	}

	return executeAuditWithConfig(ctx, stdin, stdout, stderr, config)
}

func executeAuditWithConfig(ctx context.Context, stdin io.Reader, stdout io.Writer, stderr io.Writer, config model.AuditConfig) int {
	resolvedConfig, err := resolveAuditConfig(stdin, stderr, config)
	if err != nil {
		return writeUsageError(stderr, err, true)
	}
	config = resolvedConfig

	debugLogger, closeDebugLogger, err := openDebugLogger(config)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return int(model.ExitCodeAuditFailed)
	}
	defer closeDebugLogger()

	if shouldUseTUI(stdin, stdout, config) {
		return executeAuditWithTUI(ctx, stdin, stdout, stderr, config, debugLogger)
	}

	reporter, err := reporterFor(config.Format)
	if err != nil {
		return writeUsageError(stderr, err, true)
	}

	execution, err := newExecutionContext(config, debugLogger)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return int(model.ExitCodeAuditFailed)
	}

	progressBus := newProgressBus(stdout, config, debugLogger)
	defer closeProgressBus(progressBus)

	writeOnboarding(stdout, config)

	outputs, closeOutputs, err := buildAuditOutputs(config, stdout, reporter)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return int(model.ExitCodeAuditFailed)
	}
	defer closeOutputs()

	auditOrchestrator := orchestrator.Orchestrator{
		Execution:   execution,
		Discovery:   discovery.NewServiceForAudit(execution.Config),
		Checks:      checks.Registered(),
		Outputs:     outputs,
		ProgressBus: progressBus,
	}

	auditReport, err := auditOrchestrator.Run(ctx)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return int(model.ExitCodeAuditFailed)
	}

	runPostProcessing(stderr, config, auditReport)
	writeFooter(stdout, auditReport, config)

	return int(model.ExitCodeForReport(auditReport))
}

func resolveAuditConfig(stdin io.Reader, stderr io.Writer, config model.AuditConfig) (model.AuditConfig, error) {
	resolvedConfig, err := ux.Prompter{Input: stdin, Output: stderr}.ResolveAuditConfig(config)
	if err != nil {
		return model.AuditConfig{}, err
	}

	if err := resolvedConfig.ValidateResolved(); err != nil {
		return model.AuditConfig{}, err
	}

	return resolvedConfig, nil
}

func newExecutionContext(config model.AuditConfig, debugLogger interface{ LogCommand(model.CommandResult, error) }) (model.ExecutionContext, error) {
	commandRunner := runner.NewCommandRunner(config.CommandTimeout, config.MaxOutputBytes, runner.DefaultAllowlist())
	if debugLogger != nil {
		commandRunner.SetObserver(debugLogger.LogCommand)
	}
	return runner.NewExecutionContext(config, commandRunner)
}

func (app App) newAuditCommand(ctx context.Context) *cobra.Command {
	cmd := newAuditFlagCommand()
	cmd.Use = "audit"
	cmd.Short = "Run the read-only audit workflow"
	cmd.Args = cobra.NoArgs
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		config, err := parseAuditConfigFromCommand(cmd)
		if err != nil {
			return newUsageError(err, printAuditHelp)
		}

		exitCode := executeAuditWithConfig(ctx, app.stdin, cmd.OutOrStdout(), cmd.ErrOrStderr(), config)
		if exitCode == 0 {
			return nil
		}

		return &commandError{code: exitCode}
	}
	cmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		printAuditHelp(cmd.OutOrStdout())
	})
	cmd.SetFlagErrorFunc(func(cmd *cobra.Command, err error) error {
		return newUsageError(err, printAuditHelp)
	})

	return cmd
}

func printAuditHelp(writer io.Writer) {
	fmt.Fprint(writer, strings.TrimSpace(ux.AuditHelp()))
	fmt.Fprintln(writer)
}

func writeUsageError(stderr io.Writer, err error, withHelp bool) int {
	fmt.Fprintln(stderr, err)
	if !withHelp {
		return int(model.ExitCodeUsageError)
	}

	fmt.Fprintln(stderr)
	printAuditHelp(stderr)

	return int(model.ExitCodeUsageError)
}
