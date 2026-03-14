package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nagi1/larainspect/internal/model"
)

func TestRunPostProcessingNilStderr(t *testing.T) {
	t.Parallel()
	runPostProcessing(nil, model.AuditConfig{}, model.Report{})
}

func TestRunPostProcessingBaselineSaveError(t *testing.T) {
	t.Parallel()
	var stderr bytes.Buffer
	cfg := model.AuditConfig{UpdateBaselinePath: "/dev/null/bad/baseline.json"}
	runPostProcessing(&stderr, cfg, model.Report{})
	if !strings.Contains(stderr.String(), "warning: unable to write baseline") {
		t.Fatalf("expected baseline warning, got %q", stderr.String())
	}
}

func TestRunPostProcessingStoreSaveError(t *testing.T) {
	t.Parallel()
	var stderr bytes.Buffer
	cfg := model.AuditConfig{StoreDir: "/dev/null/bad/store"}
	runPostProcessing(&stderr, cfg, model.Report{})
	if !strings.Contains(stderr.String(), "warning: unable to persist scan history") {
		t.Fatalf("expected store warning, got %q", stderr.String())
	}
}

func TestVersionCommandHelp(t *testing.T) {
	t.Parallel()
	app := App{stdout: io.Discard, stderr: io.Discard}
	cmd := app.newVersionCommand()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"--help"})
	_ = cmd.Execute()
	if !strings.Contains(buf.String(), "larainspect") {
		t.Fatalf("expected version in help output, got %q", buf.String())
	}
}

func TestRootCommandFlagError(t *testing.T) {
	t.Parallel()
	app := App{stdout: io.Discard, stderr: io.Discard}
	cmd := app.newRootCommand(context.Background())
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"--bogus-flag"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for unknown flag")
	}
}

func TestExecuteAuditWithConfigScopeAppNoPath(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	exitCode := executeAuditWithConfig(context.Background(), strings.NewReader(""), &stdout, &stderr, model.AuditConfig{
		Scope:     model.ScanScopeApp,
		AppPath:   "",
		Format:    model.OutputFormatJSON,
		Verbosity: model.VerbosityQuiet,
	})
	if exitCode != int(model.ExitCodeUsageError) {
		t.Fatalf("expected usage error exit, got %d stderr=%q", exitCode, stderr.String())
	}
}

func TestNewAuditCommandRunESuccess(t *testing.T) {
	t.Parallel()
	app := App{
		stdin:  strings.NewReader(""),
		stdout: io.Discard,
		stderr: io.Discard,
	}
	cmd := app.newAuditCommand(context.Background())
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"--format", "json", "--verbosity", "quiet"})
	err := cmd.Execute()
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
}

func TestNewAuditCommandFlagError(t *testing.T) {
	t.Parallel()
	app := App{
		stdin:  strings.NewReader(""),
		stdout: io.Discard,
		stderr: io.Discard,
	}
	cmd := app.newAuditCommand(context.Background())
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"--no-such-flag"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for unknown flag")
	}
}

func TestLoadAuditConfigFileNotFound(t *testing.T) {
	t.Parallel()
	_, err := loadAuditConfigFile(filepath.Join(t.TempDir(), "missing.yaml"))
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestParseAuditConfigFromCommandWithBadConfigFile(t *testing.T) {
	t.Parallel()
	badFile := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(badFile, []byte("{{invalid yaml"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := newAuditFlagCommand()
	cmd.SetArgs([]string{"--config", badFile})
	if err := cmd.ParseFlags([]string{"--config", badFile}); err != nil {
		t.Fatal(err)
	}
	_, err := parseAuditConfigFromCommand(cmd)
	if err == nil {
		t.Fatal("expected error for bad config file")
	}
}

func TestParseAuditConfigFromCommandValidateError(t *testing.T) {
	t.Parallel()
	cfgFile := filepath.Join(t.TempDir(), "test.yaml")
	if err := os.WriteFile(cfgFile, []byte("audit:\n  color: bogus-color-mode\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := newAuditFlagCommand()
	cmd.SetArgs([]string{"--config", cfgFile})
	if err := cmd.ParseFlags([]string{"--config", cfgFile}); err != nil {
		t.Fatal(err)
	}
	_, err := parseAuditConfigFromCommand(cmd)
	if err == nil {
		t.Fatal("expected validation error")
	}
	if !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("expected validation error, got %v", err)
	}
}

func TestApplyFileConfigAuditScanRoots(t *testing.T) {
	t.Parallel()
	cfgFile := filepath.Join(t.TempDir(), "roots.yaml")
	yamlContent := "audit:\n  scan_roots:\n    - /opt/app1\n    - /opt/app2\n"
	if err := os.WriteFile(cfgFile, []byte(yamlContent), 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := loadAuditConfigFile(cfgFile)
	if err != nil {
		t.Fatal(err)
	}
	if len(config.ScanRoots) != 2 || config.ScanRoots[0] != "/opt/app1" {
		t.Fatalf("expected scan_roots [/opt/app1 /opt/app2], got %v", config.ScanRoots)
	}
}

func TestApplyFileConfigAuditBadTimeout(t *testing.T) {
	t.Parallel()
	cfgFile := filepath.Join(t.TempDir(), "bad-timeout.yaml")
	yamlContent := "audit:\n  command_timeout: not-a-duration\n"
	if err := os.WriteFile(cfgFile, []byte(yamlContent), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadAuditConfigFile(cfgFile)
	if err == nil {
		t.Fatal("expected error for bad timeout")
	}
	if !strings.Contains(err.Error(), "command_timeout") {
		t.Fatalf("expected timeout parse error, got %v", err)
	}
}

func TestExecuteAuditWithConfigBuildOutputsError(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	exitCode := executeAuditWithConfig(context.Background(), strings.NewReader(""), &stdout, &stderr, model.AuditConfig{
		Format:         model.OutputFormatJSON,
		Verbosity:      model.VerbosityQuiet,
		ReportJSONPath: "/dev/null/nonexistent/report.json",
	})
	if exitCode != int(model.ExitCodeAuditFailed) {
		t.Fatalf("expected audit failed exit code, got %d stderr=%q", exitCode, stderr.String())
	}
}

func TestParseAuditConfigFlagParseError(t *testing.T) {
	t.Parallel()
	_, _, err := parseAuditConfig([]string{"--command-timeout", "not-a-duration"})
	if err == nil {
		t.Fatal("expected flag parse error")
	}
}

func TestApplyFileConfigVulnCheck(t *testing.T) {
	t.Parallel()
	cfgFile := filepath.Join(t.TempDir(), "vuln.yaml")
	if err := os.WriteFile(cfgFile, []byte("audit:\n  vuln_check: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := loadAuditConfigFile(cfgFile)
	if err != nil {
		t.Fatal(err)
	}
	if !config.VulnCheck {
		t.Fatal("expected vuln_check=true")
	}
}

func TestApplyFileConfigDebugLogPath(t *testing.T) {
	t.Parallel()
	cfgFile := filepath.Join(t.TempDir(), "debug.yaml")
	if err := os.WriteFile(cfgFile, []byte("audit:\n  debug_log_path: /tmp/larainspect-debug.log\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := loadAuditConfigFile(cfgFile)
	if err != nil {
		t.Fatal(err)
	}
	if config.DebugLogPath != "/tmp/larainspect-debug.log" {
		t.Fatalf("expected debug_log_path to load, got %q", config.DebugLogPath)
	}
}

type errReader struct{}

func (r *errReader) Read([]byte) (int, error) { return 0, errors.New("read failure") }

func TestResolveAuditConfigPromptError(t *testing.T) {
	t.Parallel()
	_, err := resolveAuditConfig(&errReader{}, io.Discard, model.AuditConfig{
		Interactive: true,
		Scope:       model.ScanScopeAuto,
		Format:      model.OutputFormatJSON,
	})
	if err == nil {
		t.Fatal("expected error from broken stdin")
	}
}

func TestNewAuditCommandRunEConfigError(t *testing.T) {
	t.Parallel()
	app := App{stdin: strings.NewReader(""), stdout: io.Discard, stderr: io.Discard}
	cmd := app.newAuditCommand(context.Background())
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"--config", filepath.Join(t.TempDir(), "nonexistent.yaml")})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for nonexistent config")
	}
}

func TestDecodeJSONConfigBrokenSecondValue(t *testing.T) {
	t.Parallel()
	cfgFile := filepath.Join(t.TempDir(), "broken.json")
	if err := os.WriteFile(cfgFile, []byte("{\"version\":1}{\"broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadAuditConfigFile(cfgFile)
	if err == nil {
		t.Fatal("expected error for broken second JSON value")
	}
}

func TestExecuteAuditWithConfigCancelledContext(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var stdout, stderr bytes.Buffer
	exitCode := executeAuditWithConfig(ctx, strings.NewReader(""), &stdout, &stderr, model.AuditConfig{
		Format:    model.OutputFormatJSON,
		Verbosity: model.VerbosityQuiet,
	})
	if exitCode == int(model.ExitCodeUsageError) {
		t.Fatalf("should not be a usage error, got %d", exitCode)
	}
}
