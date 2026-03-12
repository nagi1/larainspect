package cli_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nagi/larainspect/internal/cli"
	"github.com/nagi/larainspect/internal/model"
)

func TestAppPrintsRootHelp(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := cli.NewApp(&stdout, &stderr).Run(context.Background(), nil)
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	if !strings.Contains(stdout.String(), "larainspect audit [flags]") {
		t.Fatalf("expected help output, got %q", stdout.String())
	}

	if !strings.Contains(stdout.String(), "Safety promises:") {
		t.Fatalf("expected safety help section, got %q", stdout.String())
	}
}

func TestAppRendersJSONAuditOutput(t *testing.T) {
	t.Parallel()

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
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := cli.NewApp(&stdout, &stderr).Run(context.Background(), []string{"audit", "--help"})
	if exitCode != 0 {
		t.Fatalf("expected help exit code 0, got %d stderr=%q", exitCode, stderr.String())
	}

	if !strings.Contains(stdout.String(), "--interactive") {
		t.Fatalf("expected interactive help flag, got %q", stdout.String())
	}

	if !strings.Contains(stdout.String(), "Accessibility:") {
		t.Fatalf("expected accessibility help section, got %q", stdout.String())
	}
}

func TestAuditScopeAppRequiresPathWithoutInteractiveMode(t *testing.T) {
	t.Parallel()

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
	t.Parallel()

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
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := cli.NewApp(&stdout, &stderr).Run(context.Background(), []string{"audit", "--verbosity", "verbose"})
	if exitCode != int(model.ExitCodeClean) {
		t.Fatalf("expected clean exit code, got %d stderr=%q", exitCode, stderr.String())
	}

	if !strings.Contains(stdout.String(), "Starting read-only audit") {
		t.Fatalf("expected onboarding output, got %q", stdout.String())
	}

	if !strings.Contains(stdout.String(), "Next steps") {
		t.Fatalf("expected next steps output, got %q", stdout.String())
	}
}

func TestQuietTerminalAuditSuppressesExtraGuidance(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := cli.NewApp(&stdout, &stderr).Run(context.Background(), []string{"audit", "--verbosity", "quiet"})
	if exitCode != int(model.ExitCodeClean) {
		t.Fatalf("expected clean exit code, got %d stderr=%q", exitCode, stderr.String())
	}

	if strings.Contains(stdout.String(), "Starting read-only audit") {
		t.Fatalf("expected quiet mode to suppress onboarding, got %q", stdout.String())
	}

	if strings.Contains(stdout.String(), "Next steps") {
		t.Fatalf("expected quiet mode to suppress footer guidance, got %q", stdout.String())
	}
}

func TestAuditReportsUnknownForNonLaravelRequestedAppPath(t *testing.T) {
	t.Parallel()

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

func TestAppReturnsUsageExitCodeForUnknownCommand(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := cli.NewApp(&stdout, &stderr).Run(context.Background(), []string{"wat"})
	if exitCode != int(model.ExitCodeUsageError) {
		t.Fatalf("expected usage exit code %d, got %d", model.ExitCodeUsageError, exitCode)
	}
}

func TestAppPrintsVersion(t *testing.T) {
	t.Parallel()

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

func TestAppPrintsRootHelpForHelpCommand(t *testing.T) {
	t.Parallel()

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

func createLaravelAppFixture(t *testing.T) string {
	t.Helper()

	rootPath := t.TempDir()
	for _, relativePath := range []string{"bootstrap", "public"} {
		if err := os.MkdirAll(filepath.Join(rootPath, relativePath), 0o755); err != nil {
			t.Fatalf("MkdirAll(%q) error = %v", relativePath, err)
		}
	}

	writeFixtureFile(t, filepath.Join(rootPath, "artisan"), "#!/usr/bin/env php\n")
	writeFixtureFile(t, filepath.Join(rootPath, "bootstrap/app.php"), "<?php return app();\n")
	writeFixtureFile(t, filepath.Join(rootPath, "public/index.php"), "<?php require __DIR__.'/../vendor/autoload.php';\n")
	writeFixtureFile(t, filepath.Join(rootPath, "composer.json"), `{"name":"acme/shop","require":{"laravel/framework":"^11.0"}}`)

	return rootPath
}

func writeFixtureFile(t *testing.T, path string, contents string) {
	t.Helper()

	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", path, err)
	}
}
