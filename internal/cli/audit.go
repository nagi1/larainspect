package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/nagi/larainspect/internal/checks"
	"github.com/nagi/larainspect/internal/discovery"
	"github.com/nagi/larainspect/internal/model"
	"github.com/nagi/larainspect/internal/report"
	jsonreport "github.com/nagi/larainspect/internal/report/json"
	"github.com/nagi/larainspect/internal/report/terminal"
	"github.com/nagi/larainspect/internal/runner"
	"github.com/nagi/larainspect/internal/ux"
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
		writeFlagError(stderr, err, printAuditHelp)
		return int(model.ExitCodeUsageError)
	}

	config, err = resolveAuditConfig(stdin, stderr, config)
	if err != nil {
		return writeUsageError(stderr, err, true)
	}

	reporter, err := reporterFor(config.Format)
	if err != nil {
		return writeUsageError(stderr, err, true)
	}

	execution, err := newExecutionContext(config)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return int(model.ExitCodeAuditFailed)
	}

	auditReport, err := runAudit(ctx, execution)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return int(model.ExitCodeAuditFailed)
	}

	writeOnboarding(stdout, config)
	if err := reporter.Render(stdout, auditReport); err != nil {
		fmt.Fprintln(stderr, err)
		return int(model.ExitCodeAuditFailed)
	}
	writeFooter(stdout, auditReport, config)

	return int(model.ExitCodeForReport(auditReport))
}

func parseAuditConfig(args []string) (model.AuditConfig, bool, error) {
	flagSet := newFlagSet("audit")
	format := flagSet.String("format", model.OutputFormatTerminal, "Output format: terminal or json")
	verbosity := flagSet.String("verbosity", string(model.VerbosityNormal), "Output detail: quiet, normal, or verbose")
	scope := flagSet.String("scope", string(model.ScanScopeAuto), "Scan scope: auto, host, or app")
	appPath := flagSet.String("app-path", "", "App path to prioritize when scope=app")
	interactive := flagSet.Bool("interactive", false, "Enable guided prompts for missing app-focused input")
	colorMode := flagSet.String("color", string(model.ColorModeAuto), "Color preference: auto, always, or never")
	noColor := flagSet.Bool("no-color", false, "Shortcut for --color never")
	screenReader := flagSet.Bool("screen-reader", false, "Prefer concise, explicit guidance for screen-reader use")
	commandTimeout := flagSet.Duration("command-timeout", 2*time.Second, "Timeout for one allowlisted command")
	maxOutputBytes := flagSet.Int("max-output-bytes", 64*1024, "Maximum bytes captured per command stream")
	workerLimit := flagSet.Int("worker-limit", runner.DefaultWorkerLimit(), "Reserved worker cap for bounded concurrency")

	if err := flagSet.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return model.AuditConfig{}, true, nil
		}
		return model.AuditConfig{}, false, err
	}

	if *noColor {
		*colorMode = string(model.ColorModeNever)
	}

	config := model.AuditConfig{
		Format:         model.NormalizeOutputFormat(*format),
		CommandTimeout: *commandTimeout,
		MaxOutputBytes: *maxOutputBytes,
		WorkerLimit:    *workerLimit,
		Verbosity:      model.Verbosity(strings.ToLower(strings.TrimSpace(*verbosity))),
		Scope:          model.ScanScope(strings.ToLower(strings.TrimSpace(*scope))),
		Interactive:    *interactive,
		AppPath:        strings.TrimSpace(*appPath),
		ColorMode:      model.ColorMode(strings.ToLower(strings.TrimSpace(*colorMode))),
		ScreenReader:   *screenReader,
	}

	if err := config.Validate(); err != nil {
		return model.AuditConfig{}, false, err
	}

	return config, false, nil
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

func newExecutionContext(config model.AuditConfig) (model.ExecutionContext, error) {
	commandRunner := runner.NewCommandRunner(config.CommandTimeout, config.MaxOutputBytes, runner.DefaultAllowlist())
	return runner.NewExecutionContext(config, commandRunner)
}

func runAudit(ctx context.Context, execution model.ExecutionContext) (model.Report, error) {
	auditor := runner.Auditor{
		Discovery: discovery.NoopService{},
		Checks:    checks.Registered(),
	}

	return auditor.Run(ctx, execution)
}

func writeOnboarding(stdout io.Writer, config model.AuditConfig) {
	if !config.UsesTerminalOutput() {
		return
	}

	onboarding := ux.Onboarding(config)
	if onboarding == "" {
		return
	}

	fmt.Fprint(stdout, onboarding)
}

func writeFooter(stdout io.Writer, report model.Report, config model.AuditConfig) {
	if !config.UsesTerminalOutput() {
		return
	}

	footer := ux.Footer(report, config)
	if footer == "" {
		return
	}

	fmt.Fprintf(stdout, "\n%s", footer)
}

func reporterFor(format string) (report.Reporter, error) {
	switch model.NormalizeOutputFormat(format) {
	case model.OutputFormatTerminal:
		return terminal.NewReporter(), nil
	case model.OutputFormatJSON:
		return jsonreport.NewReporter(), nil
	default:
		return nil, errors.New("unsupported format; use terminal or json")
	}
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
