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
	flagSet := newFlagSet("audit")
	format := flagSet.String("format", "terminal", "Output format: terminal or json")
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
		if errors.Is(err, flag.ErrHelp) {
			printAuditHelp(stdout)
			return 0
		}

		writeFlagError(stderr, err, printAuditHelp)
		return int(model.ExitCodeUsageError)
	}

	reporter, err := reporterFor(*format)
	if err != nil {
		fmt.Fprintln(stderr, err)
		fmt.Fprintln(stderr)
		printAuditHelp(stderr)
		return int(model.ExitCodeUsageError)
	}

	if *noColor {
		*colorMode = string(model.ColorModeNever)
	}

	config := model.AuditConfig{
		Format:         strings.ToLower(strings.TrimSpace(*format)),
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
		fmt.Fprintln(stderr, err)
		fmt.Fprintln(stderr)
		printAuditHelp(stderr)
		return int(model.ExitCodeUsageError)
	}

	resolvedConfig, err := ux.Prompter{Input: stdin, Output: stderr}.ResolveAuditConfig(config)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return int(model.ExitCodeUsageError)
	}

	if resolvedConfig.Scope == model.ScanScopeApp && strings.TrimSpace(resolvedConfig.AppPath) == "" {
		fmt.Fprintln(stderr, "scope=app requires --app-path, or re-run with --interactive for guided input")
		fmt.Fprintln(stderr)
		printAuditHelp(stderr)
		return int(model.ExitCodeUsageError)
	}

	commandRunner := runner.NewCommandRunner(*commandTimeout, *maxOutputBytes, runner.DefaultAllowlist())
	execution, err := runner.NewExecutionContext(resolvedConfig, commandRunner)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return int(model.ExitCodeAuditFailed)
	}

	auditor := runner.Auditor{
		Discovery:   discovery.NoopService{},
		Checks:      checks.Registered(),
		Correlators: nil,
	}

	auditReport, err := auditor.Run(ctx, execution)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return int(model.ExitCodeAuditFailed)
	}

	if resolvedConfig.Format == "terminal" {
		if onboarding := ux.Onboarding(resolvedConfig); onboarding != "" {
			fmt.Fprint(stdout, onboarding)
		}
	}

	if err := reporter.Render(stdout, auditReport); err != nil {
		fmt.Fprintln(stderr, err)
		return int(model.ExitCodeAuditFailed)
	}

	if resolvedConfig.Format == "terminal" {
		if footer := ux.Footer(auditReport, resolvedConfig); footer != "" {
			fmt.Fprintf(stdout, "\n%s", footer)
		}
	}

	return int(model.ExitCodeForReport(auditReport))
}

func reporterFor(format string) (report.Reporter, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "terminal", "":
		return terminal.NewReporter(), nil
	case "json":
		return jsonreport.NewReporter(), nil
	default:
		return nil, errors.New("unsupported format; use terminal or json")
	}
}

func printAuditHelp(writer io.Writer) {
	fmt.Fprint(writer, strings.TrimSpace(ux.AuditHelp()))
	fmt.Fprintln(writer)
}
