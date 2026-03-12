package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestRunPrintsHelpWithoutArgs(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := run(context.Background(), nil, strings.NewReader(""), &stdout, &stderr)
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	if !strings.Contains(stdout.String(), "Read-only Laravel VPS auditor for operators under pressure.") {
		t.Fatalf("expected root help output, got %q", stdout.String())
	}
}

func TestRunHandlesVersionCommand(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := run(context.Background(), []string{"version"}, strings.NewReader(""), &stdout, &stderr)
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	if !strings.Contains(stdout.String(), "larainspect dev") {
		t.Fatalf("expected version output, got %q", stdout.String())
	}
}
