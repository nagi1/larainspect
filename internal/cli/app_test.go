package cli_test

import (
	"bytes"
	"context"
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

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := cli.NewAppWithInput(strings.NewReader("app\n/var/www/shop\n"), &stdout, &stderr).Run(
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

func TestAppReturnsUsageExitCodeForUnknownCommand(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := cli.NewApp(&stdout, &stderr).Run(context.Background(), []string{"wat"})
	if exitCode != int(model.ExitCodeUsageError) {
		t.Fatalf("expected usage exit code %d, got %d", model.ExitCodeUsageError, exitCode)
	}
}
