package main

import (
	"bytes"
	"context"
	"os"
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

func TestMainUsesExitFunc(t *testing.T) {
	originalExitFunc := exitFunc
	originalArgs := os.Args
	originalStdout := os.Stdout
	originalStderr := os.Stderr

	t.Cleanup(func() {
		exitFunc = originalExitFunc
		os.Args = originalArgs
		os.Stdout = originalStdout
		os.Stderr = originalStderr
	})

	stdoutFile, err := os.CreateTemp(t.TempDir(), "stdout")
	if err != nil {
		t.Fatalf("CreateTemp(stdout) error = %v", err)
	}
	defer stdoutFile.Close()

	stderrFile, err := os.CreateTemp(t.TempDir(), "stderr")
	if err != nil {
		t.Fatalf("CreateTemp(stderr) error = %v", err)
	}
	defer stderrFile.Close()

	var exitCode int
	exitFunc = func(code int) {
		exitCode = code
	}

	os.Args = []string{"larainspect", "version"}
	os.Stdout = stdoutFile
	os.Stderr = stderrFile

	main()

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}
}
