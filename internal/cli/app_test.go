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

func TestAppReturnsUsageExitCodeForUnknownCommand(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := cli.NewApp(&stdout, &stderr).Run(context.Background(), []string{"wat"})
	if exitCode != int(model.ExitCodeUsageError) {
		t.Fatalf("expected usage exit code %d, got %d", model.ExitCodeUsageError, exitCode)
	}
}
