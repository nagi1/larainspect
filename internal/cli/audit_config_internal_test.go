package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nagi1/larainspect/internal/model"
	"github.com/nagi1/larainspect/internal/report/terminal"
)

func TestParseAuditConfigCollectsScanRoots(t *testing.T) {
	config, helpRequested, err := parseAuditConfig([]string{"--scan-root", "/var/www", "--scan-root", "/srv/apps"})
	if err != nil {
		t.Fatalf("parseAuditConfig() error = %v", err)
	}
	if helpRequested {
		t.Fatal("expected helpRequested to be false")
	}
	if len(config.ScanRoots) != 2 {
		t.Fatalf("expected two scan roots, got %+v", config.ScanRoots)
	}
	if config.ScanRoots[0] != "/var/www" || config.ScanRoots[1] != "/srv/apps" {
		t.Fatalf("unexpected scan roots %+v", config.ScanRoots)
	}
}

func TestParseAuditConfigSupportsNoColorShortcut(t *testing.T) {
	config, helpRequested, err := parseAuditConfig([]string{"--no-color"})
	if err != nil {
		t.Fatalf("parseAuditConfig() error = %v", err)
	}
	if helpRequested {
		t.Fatal("expected helpRequested to be false")
	}
	if config.ColorMode != model.ColorModeNever {
		t.Fatalf("expected --no-color to force never, got %q", config.ColorMode)
	}
}

func TestParseAuditConfigReturnsHelpRequested(t *testing.T) {
	_, helpRequested, err := parseAuditConfig([]string{"--help"})
	if err != nil {
		t.Fatalf("parseAuditConfig() error = %v", err)
	}
	if !helpRequested {
		t.Fatal("expected helpRequested to be true")
	}
}

func TestParseAuditConfigRejectsUnexpectedArguments(t *testing.T) {
	_, helpRequested, err := parseAuditConfig([]string{"unexpected"})
	if err == nil {
		t.Fatal("expected unexpected argument error")
	}
	if helpRequested {
		t.Fatal("expected helpRequested to be false")
	}
}

func TestParseAuditConfigLoadsExplicitConfigFileAndAppliesFlagOverrides(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "larainspect.json")
	writeConfigFileForTest(t, configPath, `{
  "version": 1,
  "output": {
    "format": "json",
    "verbosity": "quiet"
  },
  "server": {
    "os": "fedora"
  },
  "advanced": {
    "command_timeout": "7s"
  }
}`)

	config, helpRequested, err := parseAuditConfig([]string{
		"--config", configPath,
		"--verbosity", "verbose",
		"--scope", "host",
	})
	if err != nil {
		t.Fatalf("parseAuditConfig() error = %v", err)
	}
	if helpRequested {
		t.Fatal("expected helpRequested to be false")
	}
	if config.Format != model.OutputFormatJSON {
		t.Fatalf("expected config file format to be loaded, got %q", config.Format)
	}
	if config.Verbosity != model.VerbosityVerbose || config.Scope != model.ScanScopeHost {
		t.Fatalf("expected flag overrides to win, got %+v", config)
	}
	if config.NormalizedOSFamily() != "rhel" {
		t.Fatalf("expected fedora profile normalization, got %q", config.NormalizedOSFamily())
	}
}

func TestParseAuditConfigAutoLoadsDefaultConfigFile(t *testing.T) {
	workingDirectory := t.TempDir()
	writeConfigFileForTest(t, filepath.Join(workingDirectory, "larainspect.json"), `{
  "version": 1,
  "laravel": {
    "scope": "host"
  }
}`)

	originalWorkingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd() error = %v", err)
	}
	if err := os.Chdir(workingDirectory); err != nil {
		t.Fatalf("Chdir() error = %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(originalWorkingDirectory)
	})

	config, helpRequested, err := parseAuditConfig(nil)
	if err != nil {
		t.Fatalf("parseAuditConfig() error = %v", err)
	}
	if helpRequested {
		t.Fatal("expected helpRequested to be false")
	}
	if config.Scope != model.ScanScopeHost {
		t.Fatalf("expected auto-loaded config scope, got %+v", config)
	}
}

func TestExecuteAuditWithConfigRejectsUnsupportedFormat(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := executeAuditWithConfig(context.Background(), strings.NewReader(""), &stdout, &stderr, model.AuditConfig{
		Format: "bad",
	})
	if exitCode != int(model.ExitCodeUsageError) {
		t.Fatalf("expected usage exit code, got %d", exitCode)
	}
	if !strings.Contains(stderr.String(), "unsupported format") {
		t.Fatalf("expected unsupported format error, got %q", stderr.String())
	}
}

func TestBuildAuditOutputsReturnsMarkdownFileErrorAfterCreatingJSONOutput(t *testing.T) {
	var stdout bytes.Buffer
	jsonPath := filepath.Join(t.TempDir(), "report.json")
	_, closeOutputs, err := buildAuditOutputs(model.AuditConfig{
		Format:             model.OutputFormatTerminal,
		ReportJSONPath:     jsonPath,
		ReportMarkdownPath: filepath.Join(t.TempDir(), "missing", "report.md"),
	}, &stdout, terminal.NewReporter())
	defer closeOutputs()

	if err == nil {
		t.Fatal("expected markdown file creation error")
	}
}

func TestTrimStringValuesRemovesEmptyEntries(t *testing.T) {
	values := trimStringValues([]string{" /var/www ", "", "   ", "/srv/apps"})
	if len(values) != 2 {
		t.Fatalf("expected two values, got %+v", values)
	}
	if values[0] != "/var/www" || values[1] != "/srv/apps" {
		t.Fatalf("unexpected trimmed values %+v", values)
	}
}

func TestApplyFlagOverridesAllFlags(t *testing.T) {
	config := model.DefaultAuditConfig()
	setFlags := map[string]struct{}{
		"config":               {},
		"format":               {},
		"report-json-path":     {},
		"report-markdown-path": {},
		"report-sarif-path":    {},
		"report-html-path":     {},
		"debug-log-path":       {},
		"baseline":             {},
		"update-baseline":      {},
		"store-dir":            {},
		"command-timeout":      {},
		"max-output-bytes":     {},
		"worker-limit":         {},
		"verbosity":            {},
		"scope":                {},
		"interactive":          {},
		"app-path":             {},
		"scan-root":            {},
		"color":                {},
		"no-color":             {},
		"screen-reader":        {},
		"vuln-check":           {},
	}
	overrides := auditFlagOverrides{
		configPath:         "/custom/config.yaml",
		format:             "json",
		reportJSONPath:     "/tmp/report.json",
		reportMarkdownPath: "/tmp/report.md",
		reportSARIFPath:    "/tmp/report.sarif",
		reportHTMLPath:     "/tmp/report.html",
		debugLogPath:       "/tmp/larainspect-debug.log",
		baselinePath:       "/tmp/baseline.json",
		updateBaselinePath: "/tmp/update-baseline.json",
		storeDir:           "/tmp/store",
		commandTimeout:     10000000000,
		maxOutputBytes:     1024,
		workerLimit:        4,
		verbosity:          "verbose",
		scope:              "host",
		interactive:        true,
		appPath:            "/var/www/app",
		scanRoots:          []string{"/srv/apps"},
		colorMode:          "always",
		noColor:            true,
		screenReader:       true,
		vulnCheck:          true,
	}

	applyFlagOverrides(&config, setFlags, overrides)

	if config.ConfigPath != "/custom/config.yaml" {
		t.Errorf("ConfigPath = %q", config.ConfigPath)
	}
	if config.Format != model.OutputFormatJSON {
		t.Errorf("Format = %q", config.Format)
	}
	if config.ReportJSONPath != "/tmp/report.json" {
		t.Errorf("ReportJSONPath = %q", config.ReportJSONPath)
	}
	if config.ReportMarkdownPath != "/tmp/report.md" {
		t.Errorf("ReportMarkdownPath = %q", config.ReportMarkdownPath)
	}
	if config.ReportSARIFPath != "/tmp/report.sarif" {
		t.Errorf("ReportSARIFPath = %q", config.ReportSARIFPath)
	}
	if config.ReportHTMLPath != "/tmp/report.html" {
		t.Errorf("ReportHTMLPath = %q", config.ReportHTMLPath)
	}
	if config.DebugLogPath != "/tmp/larainspect-debug.log" {
		t.Errorf("DebugLogPath = %q", config.DebugLogPath)
	}
	if config.BaselinePath != "/tmp/baseline.json" {
		t.Errorf("BaselinePath = %q", config.BaselinePath)
	}
	if config.UpdateBaselinePath != "/tmp/update-baseline.json" {
		t.Errorf("UpdateBaselinePath = %q", config.UpdateBaselinePath)
	}
	if config.StoreDir != "/tmp/store" {
		t.Errorf("StoreDir = %q", config.StoreDir)
	}
	if config.WorkerLimit != 4 {
		t.Errorf("WorkerLimit = %d", config.WorkerLimit)
	}
	if config.MaxOutputBytes != 1024 {
		t.Errorf("MaxOutputBytes = %d", config.MaxOutputBytes)
	}
	if config.Verbosity != model.VerbosityVerbose {
		t.Errorf("Verbosity = %q", config.Verbosity)
	}
	if config.Scope != model.ScanScopeHost {
		t.Errorf("Scope = %q", config.Scope)
	}
	if !config.Interactive {
		t.Error("Interactive should be true")
	}
	if config.AppPath != "/var/www/app" {
		t.Errorf("AppPath = %q", config.AppPath)
	}
	if len(config.ScanRoots) != 1 || config.ScanRoots[0] != "/srv/apps" {
		t.Errorf("ScanRoots = %v", config.ScanRoots)
	}
	if config.ColorMode != model.ColorModeNever {
		t.Errorf("ColorMode = %q", config.ColorMode)
	}
	if !config.ScreenReader {
		t.Error("ScreenReader should be true")
	}
	if !config.VulnCheck {
		t.Error("VulnCheck should be true")
	}
}

func TestParseAuditConfigSupportsScreenReader(t *testing.T) {
	config, _, err := parseAuditConfig([]string{"--screen-reader"})
	if err != nil {
		t.Fatalf("parseAuditConfig() error = %v", err)
	}
	if !config.ScreenReader {
		t.Fatal("expected ScreenReader to be true")
	}
}

func TestParseAuditConfigSupportsVulnCheck(t *testing.T) {
	config, _, err := parseAuditConfig([]string{"--vuln-check"})
	if err != nil {
		t.Fatalf("parseAuditConfig() error = %v", err)
	}
	if !config.VulnCheck {
		t.Fatal("expected VulnCheck to be true")
	}
}

func TestParseAuditConfigSupportsDebugLogPath(t *testing.T) {
	config, _, err := parseAuditConfig([]string{"--debug-log-path", "/tmp/larainspect-debug.log"})
	if err != nil {
		t.Fatalf("parseAuditConfig() error = %v", err)
	}
	if config.DebugLogPath != "/tmp/larainspect-debug.log" {
		t.Fatalf("expected DebugLogPath to be set, got %q", config.DebugLogPath)
	}
}

func TestParseAuditConfigSupportsWorkerLimit(t *testing.T) {
	config, _, err := parseAuditConfig([]string{"--worker-limit", "2"})
	if err != nil {
		t.Fatalf("parseAuditConfig() error = %v", err)
	}
	if config.WorkerLimit != 2 {
		t.Fatalf("expected WorkerLimit 2, got %d", config.WorkerLimit)
	}
}

func TestExecuteAuditWithConfigJSONFormat(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := executeAuditWithConfig(context.Background(), strings.NewReader(""), &stdout, &stderr, model.AuditConfig{
		Format:    model.OutputFormatJSON,
		Verbosity: model.VerbosityQuiet,
	})
	if exitCode != int(model.ExitCodeClean) {
		t.Fatalf("expected clean exit code, got %d stderr=%q", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"schema_version"`) {
		t.Fatalf("expected JSON output, got %q", stdout.String())
	}
}

func TestNewAuditFlagCommand(t *testing.T) {
	cmd := newAuditFlagCommand()
	if cmd.Use != "audit" {
		t.Fatalf("expected Use=audit, got %q", cmd.Use)
	}

	for _, flagName := range auditFlagNames() {
		if cmd.Flags().Lookup(flagName) == nil {
			t.Errorf("expected flag %q to be registered", flagName)
		}
	}
}
