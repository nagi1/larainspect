package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nagi1/larainspect/internal/cli"
	"github.com/nagi1/larainspect/internal/model"
)

func TestAppPrintsRootHelp(t *testing.T) {

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := cli.NewApp(&stdout, &stderr).Run(context.Background(), nil)
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	if !strings.Contains(stdout.String(), "larainspect audit [flags]") {
		t.Fatalf("expected help output, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "larainspect controls [flags]") {
		t.Fatalf("expected controls command in root help, got %q", stdout.String())
	}

	if !strings.Contains(stdout.String(), "Safety promises:") {
		t.Fatalf("expected safety help section, got %q", stdout.String())
	}
}

func TestControlsCommandRendersTextOutput(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := cli.NewApp(&stdout, &stderr).Run(context.Background(), []string{"controls", "--status", "implemented", "--check-id", "nginx.boundaries"})
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d stderr=%q", exitCode, stderr.String())
	}

	output := stdout.String()
	if !strings.Contains(output, "larainspect normalized control map") {
		t.Fatalf("expected controls header, got %q", output)
	}
	if !strings.Contains(output, "laravel.public-docroot-boundary") {
		t.Fatalf("expected nginx-mapped control, got %q", output)
	}
	if !strings.Contains(output, "https://laravel.com/docs/11.x/deployment") {
		t.Fatalf("expected source URL, got %q", output)
	}
}

func TestControlsCommandRendersJSONOutput(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := cli.NewApp(&stdout, &stderr).Run(context.Background(), []string{"controls", "--format", "json", "--status", "partial"})
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d stderr=%q", exitCode, stderr.String())
	}

	var payload []map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("json.Unmarshal() error = %v output=%q", err, stdout.String())
	}
	if len(payload) == 0 {
		t.Fatal("expected at least one partial control")
	}
	if payload[0]["status"] != "partial" {
		t.Fatalf("expected filtered status partial, got %+v", payload[0])
	}
}

func TestAppRendersJSONAuditOutput(t *testing.T) {

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := cli.NewApp(&stdout, &stderr).Run(context.Background(), []string{"audit", "--format", "json"})
	if exitCode != int(model.ExitCodeClean) {
		t.Fatalf("expected exit code 0, got %d stderr=%q", exitCode, stderr.String())
	}

	if !strings.Contains(stdout.String(), `"schema_version": "v0alpha1"`) {
		t.Fatalf("expected json output, got %q", stdout.String())
	}

	if !strings.Contains(stdout.String(), `"critical": 0`) {
		t.Fatalf("expected stable zeroed severity buckets, got %q", stdout.String())
	}
}

func TestAuditHelpShowsUXFlags(t *testing.T) {

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := cli.NewApp(&stdout, &stderr).Run(context.Background(), []string{"audit", "--help"})
	if exitCode != 0 {
		t.Fatalf("expected help exit code 0, got %d stderr=%q", exitCode, stderr.String())
	}

	if !strings.Contains(stdout.String(), "--interactive") {
		t.Fatalf("expected interactive help flag, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "--report-markdown-path") {
		t.Fatalf("expected markdown artifact flag, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "--debug-log-path") {
		t.Fatalf("expected debug log flag, got %q", stdout.String())
	}

	if !strings.Contains(stdout.String(), "Accessibility:") {
		t.Fatalf("expected accessibility help section, got %q", stdout.String())
	}
}

func TestAuditScopeAppRequiresPathWithoutInteractiveMode(t *testing.T) {

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := cli.NewApp(&stdout, &stderr).Run(context.Background(), []string{"audit", "--scope", "app"})
	if exitCode != int(model.ExitCodeUsageError) {
		t.Fatalf("expected usage exit code, got %d", exitCode)
	}

	if !strings.Contains(stderr.String(), "scope=app requires --app-path") {
		t.Fatalf("expected helpful app-path error, got %q", stderr.String())
	}
}

func TestInteractiveAuditPromptsForAppPath(t *testing.T) {

	appPath := createLaravelAppFixture(t)
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := cli.NewAppWithInput(strings.NewReader("app\n"+appPath+"\n"), &stdout, &stderr).Run(
		context.Background(),
		[]string{"audit", "--interactive", "--format", "json"},
	)
	if exitCode != int(model.ExitCodeClean) {
		t.Fatalf("expected clean exit code, got %d stderr=%q", exitCode, stderr.String())
	}

	if !strings.Contains(stderr.String(), "Guided mode is enabled") {
		t.Fatalf("expected guided mode message, got %q", stderr.String())
	}

	if !strings.Contains(stderr.String(), "App path to inspect:") {
		t.Fatalf("expected app path prompt, got %q", stderr.String())
	}

	if !strings.Contains(stdout.String(), `"schema_version": "v0alpha1"`) {
		t.Fatalf("expected json output, got %q", stdout.String())
	}
}

func TestVerboseTerminalAuditShowsOnboardingAndNextSteps(t *testing.T) {

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := cli.NewApp(&stdout, &stderr).Run(context.Background(), []string{"audit", "--verbosity", "verbose"})
	if exitCode != int(model.ExitCodeClean) {
		t.Fatalf("expected clean exit code, got %d stderr=%q", exitCode, stderr.String())
	}

	if !strings.Contains(stdout.String(), "Starting read-only audit") {
		t.Fatalf("expected onboarding output, got %q", stdout.String())
	}

	if !strings.Contains(stdout.String(), "Audit progress") {
		t.Fatalf("expected progress output, got %q", stdout.String())
	}

	if !strings.Contains(stdout.String(), "Next steps") {
		t.Fatalf("expected next steps output, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "Stages: setup -> discovery -> checks -> correlation -> report") {
		t.Fatalf("expected stage map, got %q", stdout.String())
	}
}

func TestQuietTerminalAuditSuppressesExtraGuidance(t *testing.T) {

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := cli.NewApp(&stdout, &stderr).Run(context.Background(), []string{"audit", "--verbosity", "quiet"})
	if exitCode != int(model.ExitCodeClean) {
		t.Fatalf("expected clean exit code, got %d stderr=%q", exitCode, stderr.String())
	}

	if strings.Contains(stdout.String(), "Starting read-only audit") {
		t.Fatalf("expected quiet mode to suppress onboarding, got %q", stdout.String())
	}

	if strings.Contains(stdout.String(), "Audit progress") {
		t.Fatalf("expected quiet mode to suppress progress output, got %q", stdout.String())
	}

	if strings.Contains(stdout.String(), "Next steps") {
		t.Fatalf("expected quiet mode to suppress footer guidance, got %q", stdout.String())
	}
}

func TestAuditReportsUnknownForNonLaravelRequestedAppPath(t *testing.T) {

	appPath := filepath.Join(t.TempDir(), "not-laravel")
	if err := os.MkdirAll(appPath, 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := cli.NewApp(&stdout, &stderr).Run(context.Background(), []string{
		"audit",
		"--format", "json",
		"--scope", "app",
		"--app-path", appPath,
	})
	if exitCode != int(model.ExitCodeLowRisk) {
		t.Fatalf("expected unknown-only exit code, got %d stderr=%q", exitCode, stderr.String())
	}

	if !strings.Contains(stdout.String(), `"unknowns": 1`) {
		t.Fatalf("expected unknown count in JSON output, got %q", stdout.String())
	}
}

func TestTerminalAuditCanAlsoWriteArtifacts(t *testing.T) {

	reportPath := filepath.Join(t.TempDir(), "larainspect-report.json")
	markdownPath := filepath.Join(t.TempDir(), "larainspect-report.md")
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := cli.NewApp(&stdout, &stderr).Run(context.Background(), []string{
		"audit",
		"--report-json-path", reportPath,
		"--report-markdown-path", markdownPath,
	})
	if exitCode != int(model.ExitCodeClean) {
		t.Fatalf("expected clean exit code, got %d stderr=%q", exitCode, stderr.String())
	}

	if !strings.Contains(stdout.String(), "larainspect audit") {
		t.Fatalf("expected terminal report on stdout, got %q", stdout.String())
	}

	reportBytes, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(reportBytes, &payload); err != nil {
		t.Fatalf("Unmarshal() error = %v report=%q", err, string(reportBytes))
	}

	if payload["schema_version"] != "v0alpha1" {
		t.Fatalf("expected schema_version in JSON artifact, got %+v", payload)
	}

	markdownBytes, err := os.ReadFile(markdownPath)
	if err != nil {
		t.Fatalf("ReadFile(markdown) error = %v", err)
	}
	if !strings.Contains(string(markdownBytes), "# Larainspect Audit Report") {
		t.Fatalf("expected markdown artifact, got %q", string(markdownBytes))
	}
}

func TestAppRendersMarkdownAuditOutput(t *testing.T) {

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := cli.NewApp(&stdout, &stderr).Run(context.Background(), []string{"audit", "--format", "markdown"})
	if exitCode != int(model.ExitCodeClean) {
		t.Fatalf("expected exit code 0, got %d stderr=%q", exitCode, stderr.String())
	}

	if !strings.Contains(stdout.String(), "# Larainspect Audit Report") {
		t.Fatalf("expected markdown output, got %q", stdout.String())
	}
}

func TestAppReturnsUsageExitCodeForUnknownCommand(t *testing.T) {

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := cli.NewApp(&stdout, &stderr).Run(context.Background(), []string{"wat"})
	if exitCode != int(model.ExitCodeUsageError) {
		t.Fatalf("expected usage exit code %d, got %d", model.ExitCodeUsageError, exitCode)
	}
}

func TestAppPrintsVersion(t *testing.T) {

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := cli.NewApp(&stdout, &stderr).Run(context.Background(), []string{"version"})
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	if !strings.Contains(stdout.String(), "larainspect dev") {
		t.Fatalf("expected version output, got %q", stdout.String())
	}
}

func TestAppPrintsVersionFlag(t *testing.T) {

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := cli.NewApp(&stdout, &stderr).Run(context.Background(), []string{"--version"})
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	if !strings.Contains(stdout.String(), "larainspect dev") {
		t.Fatalf("expected version output, got %q", stdout.String())
	}
}

func TestAppPrintsVersionMetadataWhenPresent(t *testing.T) {
	originalVersion := cli.Version
	originalCommit := cli.Commit
	originalDate := cli.Date

	t.Cleanup(func() {
		cli.Version = originalVersion
		cli.Commit = originalCommit
		cli.Date = originalDate
	})

	cli.Version = "v1.2.3"
	cli.Commit = "abc1234"
	cli.Date = "2026-03-14T12:00:00Z"

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := cli.NewApp(&stdout, &stderr).Run(context.Background(), []string{"version"})
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	output := stdout.String()
	if !strings.Contains(output, "larainspect v1.2.3") {
		t.Fatalf("expected semantic version in output, got %q", output)
	}
	if !strings.Contains(output, "maintainer: Ahmed Nagi (nagi1)") {
		t.Fatalf("expected maintainer in output, got %q", output)
	}
	if !strings.Contains(output, "x: @nagiworks") {
		t.Fatalf("expected X handle in output, got %q", output)
	}
	if !strings.Contains(output, "commit: abc1234") {
		t.Fatalf("expected commit in output, got %q", output)
	}
	if !strings.Contains(output, "built: 2026-03-14T12:00:00Z") {
		t.Fatalf("expected build date in output, got %q", output)
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected empty stderr, got %q", stderr.String())
	}
}

func TestAppPrintsRootHelpForHelpCommand(t *testing.T) {

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := cli.NewApp(&stdout, &stderr).Run(context.Background(), []string{"help"})
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	if !strings.Contains(stdout.String(), "Commands:") {
		t.Fatalf("expected root help output, got %q", stdout.String())
	}
}

func TestAppPrintsAuditHelpForHelpAuditCommand(t *testing.T) {

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := cli.NewApp(&stdout, &stderr).Run(context.Background(), []string{"help", "audit"})
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	if !strings.Contains(stdout.String(), "Run the read-only audit workflow.") {
		t.Fatalf("expected audit help output, got %q", stdout.String())
	}
}

func createLaravelAppFixture(t *testing.T) string {
	t.Helper()

	rootPath := t.TempDir()
	createFixtureDir(t, filepath.Join(rootPath, "app"), 0o750)
	createFixtureDir(t, filepath.Join(rootPath, "bootstrap"), 0o750)
	createFixtureDir(t, filepath.Join(rootPath, "bootstrap/cache"), 0o770)
	createFixtureDir(t, filepath.Join(rootPath, "config"), 0o750)
	createFixtureDir(t, filepath.Join(rootPath, "database"), 0o750)
	createFixtureDir(t, filepath.Join(rootPath, "public"), 0o750)
	createFixtureDir(t, filepath.Join(rootPath, "resources"), 0o750)
	createFixtureDir(t, filepath.Join(rootPath, "routes"), 0o750)
	createFixtureDir(t, filepath.Join(rootPath, "storage"), 0o770)
	createFixtureDir(t, filepath.Join(rootPath, "vendor"), 0o750)

	writeFixtureFileWithMode(t, filepath.Join(rootPath, "artisan"), "#!/usr/bin/env php\n", 0o640)
	writeFixtureFileWithMode(t, filepath.Join(rootPath, "bootstrap/app.php"), "<?php return app();\n", 0o640)
	writeFixtureFileWithMode(t, filepath.Join(rootPath, "bootstrap/cache/config.php"), "<?php return ['app' => ['debug' => false]];\n", 0o640)
	writeFixtureFileWithMode(t, filepath.Join(rootPath, "config/app.php"), "<?php return ['name' => 'Demo'];\n", 0o640)
	writeFixtureFileWithMode(t, filepath.Join(rootPath, "public/index.php"), "<?php require __DIR__.'/../vendor/autoload.php';\n", 0o640)
	writeFixtureFileWithMode(t, filepath.Join(rootPath, "composer.json"), `{"name":"acme/shop","require":{"laravel/framework":"^11.0"}}`, 0o640)
	writeFixtureFileWithMode(t, filepath.Join(rootPath, "composer.lock"), `{"packages":[{"name":"laravel/framework","version":"v11.0.0"}]}`, 0o640)
	envPath := filepath.Join(rootPath, ".env")
	writeFixtureFileWithMode(t, envPath, "APP_KEY=base64:dGVzdHRlc3R0ZXN0dGVzdA==\nAPP_DEBUG=false\n", 0o640)

	resolvedRootPath, err := filepath.EvalSymlinks(rootPath)
	if err != nil {
		t.Fatalf("EvalSymlinks(%q) error = %v", rootPath, err)
	}

	return resolvedRootPath
}

func writeFixtureFile(t *testing.T, path string, contents string) {
	t.Helper()

	writeFixtureFileWithMode(t, path, contents, 0o644)
}

func writeFixtureFileWithMode(t *testing.T, path string, contents string, mode os.FileMode) {
	t.Helper()

	if err := os.WriteFile(path, []byte(contents), mode); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", path, err)
	}
}

func createFixtureDir(t *testing.T, path string, mode os.FileMode) {
	t.Helper()

	if err := os.MkdirAll(path, mode); err != nil {
		t.Fatalf("MkdirAll(%q) error = %v", path, err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("Chmod(%q) error = %v", path, err)
	}
}
