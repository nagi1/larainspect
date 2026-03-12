package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/nagi1/larainspect/internal/checks"
	"github.com/nagi1/larainspect/internal/discovery"
	"github.com/nagi1/larainspect/internal/model"
	"github.com/nagi1/larainspect/internal/report"
	jsonreport "github.com/nagi1/larainspect/internal/report/json"
	"github.com/nagi1/larainspect/internal/report/terminal"
	"github.com/nagi1/larainspect/internal/runner"
	"github.com/nagi1/larainspect/internal/ux"
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
	defaultConfig := model.DefaultAuditConfig()
	flagSet := newFlagSet("audit")
	configPath := flagSet.String("config", "", "Path to an audit profile JSON file")
	format := flagSet.String("format", defaultConfig.Format, "Output format: terminal or json")
	verbosity := flagSet.String("verbosity", string(defaultConfig.Verbosity), "Output detail: quiet, normal, or verbose")
	scope := flagSet.String("scope", string(defaultConfig.Scope), "Scan scope: auto, host, or app")
	appPath := flagSet.String("app-path", "", "App path to prioritize when scope=app")
	var scanRoots stringListFlag
	flagSet.Var(&scanRoots, "scan-root", "Additional root to scan for Laravel apps; may be repeated")
	interactive := flagSet.Bool("interactive", defaultConfig.Interactive, "Enable guided prompts for missing app-focused input")
	colorMode := flagSet.String("color", string(defaultConfig.ColorMode), "Color preference: auto, always, or never")
	noColor := flagSet.Bool("no-color", false, "Shortcut for --color never")
	screenReader := flagSet.Bool("screen-reader", defaultConfig.ScreenReader, "Prefer concise, explicit guidance for screen-reader use")
	commandTimeout := flagSet.Duration("command-timeout", defaultConfig.CommandTimeout, "Timeout for one allowlisted command")
	maxOutputBytes := flagSet.Int("max-output-bytes", defaultConfig.MaxOutputBytes, "Maximum bytes captured per command stream")
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

	resolvedConfigPath, err := resolveAuditConfigFilePath(*configPath)
	if err != nil {
		return model.AuditConfig{}, false, err
	}

	config := defaultConfig
	if resolvedConfigPath != "" {
		config, err = loadAuditConfigFile(resolvedConfigPath)
		if err != nil {
			return model.AuditConfig{}, false, err
		}
	}

	setFlags := map[string]struct{}{}
	flagSet.Visit(func(flag *flag.Flag) {
		setFlags[flag.Name] = struct{}{}
	})

	applyFlagOverrides(&config, setFlags, auditFlagOverrides{
		configPath:     resolvedConfigPath,
		format:         *format,
		commandTimeout: *commandTimeout,
		maxOutputBytes: *maxOutputBytes,
		workerLimit:    *workerLimit,
		verbosity:      *verbosity,
		scope:          *scope,
		interactive:    *interactive,
		appPath:        *appPath,
		scanRoots:      scanRoots.values(),
		colorMode:      *colorMode,
		screenReader:   *screenReader,
	})

	if err := config.Validate(); err != nil {
		return model.AuditConfig{}, false, err
	}

	return config, false, nil
}

type auditFlagOverrides struct {
	configPath     string
	format         string
	commandTimeout time.Duration
	maxOutputBytes int
	workerLimit    int
	verbosity      string
	scope          string
	interactive    bool
	appPath        string
	scanRoots      []string
	colorMode      string
	screenReader   bool
}

func applyFlagOverrides(config *model.AuditConfig, setFlags map[string]struct{}, overrides auditFlagOverrides) {
	if _, ok := setFlags["config"]; ok {
		config.ConfigPath = overrides.configPath
	}
	if _, ok := setFlags["format"]; ok {
		config.Format = model.NormalizeOutputFormat(overrides.format)
	}
	if _, ok := setFlags["command-timeout"]; ok {
		config.CommandTimeout = overrides.commandTimeout
	}
	if _, ok := setFlags["max-output-bytes"]; ok {
		config.MaxOutputBytes = overrides.maxOutputBytes
	}
	if _, ok := setFlags["worker-limit"]; ok {
		config.WorkerLimit = overrides.workerLimit
	}
	if _, ok := setFlags["verbosity"]; ok {
		config.Verbosity = model.Verbosity(strings.ToLower(strings.TrimSpace(overrides.verbosity)))
	}
	if _, ok := setFlags["scope"]; ok {
		config.Scope = model.ScanScope(strings.ToLower(strings.TrimSpace(overrides.scope)))
	}
	if _, ok := setFlags["interactive"]; ok {
		config.Interactive = overrides.interactive
	}
	if _, ok := setFlags["app-path"]; ok {
		config.AppPath = strings.TrimSpace(overrides.appPath)
	}
	if _, ok := setFlags["scan-root"]; ok {
		config.ScanRoots = overrides.scanRoots
	}
	if _, ok := setFlags["color"]; ok {
		config.ColorMode = model.ColorMode(strings.ToLower(strings.TrimSpace(overrides.colorMode)))
	}
	if _, ok := setFlags["no-color"]; ok {
		config.ColorMode = model.ColorModeNever
	}
	if _, ok := setFlags["screen-reader"]; ok {
		config.ScreenReader = overrides.screenReader
	}
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
		Discovery: discovery.NewServiceForAudit(execution.Config),
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

type stringListFlag struct {
	items []string
}

func (flagValue *stringListFlag) String() string {
	return strings.Join(flagValue.items, ",")
}

func (flagValue *stringListFlag) Set(value string) error {
	flagValue.items = append(flagValue.items, strings.TrimSpace(value))
	return nil
}

func (flagValue stringListFlag) values() []string {
	values := make([]string, 0, len(flagValue.items))
	for _, item := range flagValue.items {
		trimmedItem := strings.TrimSpace(item)
		if trimmedItem == "" {
			continue
		}
		values = append(values, trimmedItem)
	}

	return values
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
