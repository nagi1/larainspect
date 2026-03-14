package cli

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nagi1/larainspect/internal/model"
	"github.com/nagi1/larainspect/internal/runner"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func parseAuditConfig(args []string) (model.AuditConfig, bool, error) {
	cmd := newAuditFlagCommand()
	cmd.SetArgs(args)

	if err := cmd.ParseFlags(args); err != nil {
		if errors.Is(err, pflag.ErrHelp) {
			return model.AuditConfig{}, true, nil
		}
		return model.AuditConfig{}, false, err
	}

	helpRequested, err := cmd.Flags().GetBool("help")
	if err != nil {
		return model.AuditConfig{}, false, err
	}
	if helpRequested {
		return model.AuditConfig{}, true, nil
	}

	if len(cmd.Flags().Args()) > 0 {
		return model.AuditConfig{}, false, fmt.Errorf("unexpected arguments: %s", strings.Join(cmd.Flags().Args(), " "))
	}

	config, err := parseAuditConfigFromCommand(cmd)
	return config, false, err
}

func parseAuditConfigFromCommand(cmd *cobra.Command) (model.AuditConfig, error) {
	defaultConfig := model.DefaultAuditConfig()
	flags := cmd.Flags()

	configPath, err := flags.GetString("config")
	if err != nil {
		return model.AuditConfig{}, err
	}

	overrides, err := parseAuditFlagOverrides(flags)
	if err != nil {
		return model.AuditConfig{}, err
	}

	if overrides.noColor {
		overrides.colorMode = string(model.ColorModeNever)
	}

	resolvedConfigPath, err := resolveAuditConfigFilePath(configPath)
	if err != nil {
		return model.AuditConfig{}, err
	}

	config := defaultConfig
	if resolvedConfigPath != "" {
		config, err = loadAuditConfigFile(resolvedConfigPath)
		if err != nil {
			return model.AuditConfig{}, err
		}
	}

	applyFlagOverrides(&config, collectChangedFlags(cmd, auditFlagNames()...), overrides.withResolvedConfigPath(resolvedConfigPath))
	if err := config.Validate(); err != nil {
		return model.AuditConfig{}, err
	}

	return config, nil
}

type auditFlagOverrides struct {
	configPath         string
	format             string
	reportJSONPath     string
	reportMarkdownPath string
	reportSARIFPath    string
	reportHTMLPath     string
	debugLogPath       string
	baselinePath       string
	updateBaselinePath string
	storeDir           string
	commandTimeout     time.Duration
	maxOutputBytes     int
	workerLimit        int
	verbosity          string
	scope              string
	interactive        bool
	appPath            string
	scanRoots          []string
	colorMode          string
	noColor            bool
	screenReader       bool
	vulnCheck          bool
}

func parseAuditFlagOverrides(flags *pflag.FlagSet) (auditFlagOverrides, error) {
	format, err := flags.GetString("format")
	if err != nil {
		return auditFlagOverrides{}, err
	}
	reportJSONPath, err := flags.GetString("report-json-path")
	if err != nil {
		return auditFlagOverrides{}, err
	}
	reportMarkdownPath, err := flags.GetString("report-markdown-path")
	if err != nil {
		return auditFlagOverrides{}, err
	}
	reportSARIFPath, err := flags.GetString("report-sarif-path")
	if err != nil {
		return auditFlagOverrides{}, err
	}
	reportHTMLPath, err := flags.GetString("report-html-path")
	if err != nil {
		return auditFlagOverrides{}, err
	}
	debugLogPath, err := flags.GetString("debug-log-path")
	if err != nil {
		return auditFlagOverrides{}, err
	}
	baselinePath, err := flags.GetString("baseline")
	if err != nil {
		return auditFlagOverrides{}, err
	}
	updateBaselinePath, err := flags.GetString("update-baseline")
	if err != nil {
		return auditFlagOverrides{}, err
	}
	storeDir, err := flags.GetString("store-dir")
	if err != nil {
		return auditFlagOverrides{}, err
	}
	verbosity, err := flags.GetString("verbosity")
	if err != nil {
		return auditFlagOverrides{}, err
	}
	scope, err := flags.GetString("scope")
	if err != nil {
		return auditFlagOverrides{}, err
	}
	appPath, err := flags.GetString("app-path")
	if err != nil {
		return auditFlagOverrides{}, err
	}
	scanRoots, err := flags.GetStringArray("scan-root")
	if err != nil {
		return auditFlagOverrides{}, err
	}
	interactive, err := flags.GetBool("interactive")
	if err != nil {
		return auditFlagOverrides{}, err
	}
	colorMode, err := flags.GetString("color")
	if err != nil {
		return auditFlagOverrides{}, err
	}
	noColor, err := flags.GetBool("no-color")
	if err != nil {
		return auditFlagOverrides{}, err
	}
	screenReader, err := flags.GetBool("screen-reader")
	if err != nil {
		return auditFlagOverrides{}, err
	}
	commandTimeout, err := flags.GetDuration("command-timeout")
	if err != nil {
		return auditFlagOverrides{}, err
	}
	maxOutputBytes, err := flags.GetInt("max-output-bytes")
	if err != nil {
		return auditFlagOverrides{}, err
	}
	workerLimit, err := flags.GetInt("worker-limit")
	if err != nil {
		return auditFlagOverrides{}, err
	}
	vulnCheck, err := flags.GetBool("vuln-check")
	if err != nil {
		return auditFlagOverrides{}, err
	}

	return auditFlagOverrides{
		format:             format,
		reportJSONPath:     reportJSONPath,
		reportMarkdownPath: reportMarkdownPath,
		reportSARIFPath:    reportSARIFPath,
		reportHTMLPath:     reportHTMLPath,
		debugLogPath:       debugLogPath,
		baselinePath:       baselinePath,
		updateBaselinePath: updateBaselinePath,
		storeDir:           storeDir,
		commandTimeout:     commandTimeout,
		maxOutputBytes:     maxOutputBytes,
		workerLimit:        workerLimit,
		vulnCheck:          vulnCheck,
		verbosity:          verbosity,
		scope:              scope,
		interactive:        interactive,
		appPath:            appPath,
		scanRoots:          trimStringValues(scanRoots),
		colorMode:          colorMode,
		noColor:            noColor,
		screenReader:       screenReader,
	}, nil
}

func (overrides auditFlagOverrides) withResolvedConfigPath(configPath string) auditFlagOverrides {
	overrides.configPath = configPath
	return overrides
}

func auditFlagNames() []string {
	return []string{
		"config",
		"format",
		"report-json-path",
		"report-markdown-path",
		"report-sarif-path",
		"report-html-path",
		"debug-log-path",
		"baseline",
		"update-baseline",
		"store-dir",
		"command-timeout",
		"max-output-bytes",
		"worker-limit",
		"verbosity",
		"scope",
		"interactive",
		"app-path",
		"scan-root",
		"color",
		"no-color",
		"screen-reader",
		"vuln-check",
	}
}

func newAuditFlagCommand() *cobra.Command {
	defaultConfig := model.DefaultAuditConfig()

	cmd := &cobra.Command{
		Use:           "audit",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	flags := cmd.Flags()
	flags.String("config", "", "Path to an audit config file (YAML or JSON)")
	flags.String("format", defaultConfig.Format, "Output format: terminal, json, or markdown")
	flags.String("report-json-path", defaultConfig.ReportJSONPath, "Optional path to also write the JSON report artifact")
	flags.String("report-markdown-path", defaultConfig.ReportMarkdownPath, "Optional path to also write the Markdown report artifact")
	flags.String("report-sarif-path", defaultConfig.ReportSARIFPath, "Optional path to write a SARIF 2.1.0 report for GitHub Code Scanning")
	flags.String("report-html-path", defaultConfig.ReportHTMLPath, "Optional path to write a standalone HTML report")
	flags.String("debug-log-path", defaultConfig.DebugLogPath, "Optional path to write a developer debug log with progress events and command executions")
	flags.String("baseline", defaultConfig.BaselinePath, "Path to a baseline file; suppresses known findings")
	flags.String("update-baseline", defaultConfig.UpdateBaselinePath, "Write current findings as a new baseline to this path")
	flags.String("store-dir", defaultConfig.StoreDir, "Directory for scan history records; enables trend diffing")
	flags.String("verbosity", string(defaultConfig.Verbosity), "Output detail: quiet, normal, or verbose")
	flags.String("scope", string(defaultConfig.Scope), "Scan scope: auto, host, or app")
	flags.String("app-path", "", "App path to prioritize when scope=app")
	flags.StringArray("scan-root", nil, "Additional root to scan for Laravel apps; may be repeated")
	flags.Bool("interactive", defaultConfig.Interactive, "Enable guided prompts for missing app-focused input")
	flags.String("color", string(defaultConfig.ColorMode), "Color preference: auto, always, or never")
	flags.Bool("no-color", false, "Shortcut for --color never")
	flags.Bool("screen-reader", defaultConfig.ScreenReader, "Prefer concise, explicit guidance for screen-reader use")
	flags.Duration("command-timeout", defaultConfig.CommandTimeout, "Timeout for one allowlisted command")
	flags.Int("max-output-bytes", defaultConfig.MaxOutputBytes, "Maximum bytes captured per command stream")
	flags.Int("worker-limit", runner.DefaultWorkerLimit(), "Reserved worker cap for bounded concurrency")
	flags.Bool("vuln-check", false, "Enable live CVE checks via OSV.dev (requires network access)")
	cmd.InitDefaultHelpFlag()

	return cmd
}

func collectChangedFlags(cmd *cobra.Command, names ...string) map[string]struct{} {
	changedFlags := make(map[string]struct{}, len(names))
	for _, name := range names {
		if cmd.Flags().Changed(name) {
			changedFlags[name] = struct{}{}
		}
	}

	return changedFlags
}

func applyFlagOverrides(config *model.AuditConfig, setFlags map[string]struct{}, overrides auditFlagOverrides) {
	if _, ok := setFlags["config"]; ok {
		config.ConfigPath = overrides.configPath
	}
	if _, ok := setFlags["format"]; ok {
		config.Format = model.NormalizeOutputFormat(overrides.format)
	}
	if _, ok := setFlags["report-json-path"]; ok {
		config.ReportJSONPath = strings.TrimSpace(overrides.reportJSONPath)
	}
	if _, ok := setFlags["report-markdown-path"]; ok {
		config.ReportMarkdownPath = strings.TrimSpace(overrides.reportMarkdownPath)
	}
	if _, ok := setFlags["report-sarif-path"]; ok {
		config.ReportSARIFPath = strings.TrimSpace(overrides.reportSARIFPath)
	}
	if _, ok := setFlags["report-html-path"]; ok {
		config.ReportHTMLPath = strings.TrimSpace(overrides.reportHTMLPath)
	}
	if _, ok := setFlags["debug-log-path"]; ok {
		config.DebugLogPath = strings.TrimSpace(overrides.debugLogPath)
	}
	if _, ok := setFlags["baseline"]; ok {
		config.BaselinePath = strings.TrimSpace(overrides.baselinePath)
	}
	if _, ok := setFlags["update-baseline"]; ok {
		config.UpdateBaselinePath = strings.TrimSpace(overrides.updateBaselinePath)
	}
	if _, ok := setFlags["store-dir"]; ok {
		config.StoreDir = strings.TrimSpace(overrides.storeDir)
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
	if _, ok := setFlags["vuln-check"]; ok {
		config.VulnCheck = overrides.vulnCheck
	}
}

func trimStringValues(items []string) []string {
	values := make([]string, 0, len(items))
	for _, item := range items {
		trimmedItem := strings.TrimSpace(item)
		if trimmedItem == "" {
			continue
		}
		values = append(values, trimmedItem)
	}

	return values
}
