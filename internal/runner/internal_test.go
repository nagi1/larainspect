package runner

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nagi1/larainspect/internal/model"
)

func TestSpecificationValidateBranches(t *testing.T) {
	t.Parallel()

	spec := Specification{
		Name:            "demo",
		AllowedFlags:    map[string]struct{}{"-n": {}},
		AllowedPrefixes: []string{"--format="},
		AllowPaths:      true,
		AllowValues:     true,
		MaxArgs:         4,
	}

	validArgs := [][]string{
		{"-n"},
		{"--format=json"},
		{"/tmp/demo"},
		{"value"},
	}
	for _, args := range validArgs {
		if err := spec.Validate(args); err != nil {
			t.Fatalf("Validate(%v) error = %v", args, err)
		}
	}

	if err := spec.Validate([]string{"a", "b", "c", "d", "e"}); err == nil {
		t.Fatal("expected max args error")
	}
	if err := spec.Validate([]string{"--bad"}); err == nil {
		t.Fatal("expected allowlist error")
	}
}

func TestNewCommandRunnerDefaults(t *testing.T) {
	t.Parallel()

	commandRunner := NewCommandRunner(0, 0, nil)
	if commandRunner.timeout <= 0 || commandRunner.maxOutputBytes <= 0 || commandRunner.allowlist == nil {
		t.Fatalf("expected defaults to be applied: %+v", commandRunner)
	}
}

func TestAllowlistValidateUnknownCommand(t *testing.T) {
	t.Parallel()

	err := DefaultAllowlist().Validate(model.CommandRequest{Name: "unknown"})
	if !errors.Is(err, ErrCommandRejected) {
		t.Fatalf("expected ErrCommandRejected, got %v", err)
	}
}

func TestCommandRunnerHandlesNonZeroExitAndTruncation(t *testing.T) {
	t.Parallel()

	commandRunner := NewCommandRunner(time.Second, 4, NewAllowlist([]Specification{
		{Name: "ls", AllowPaths: true},
	}))

	result, err := commandRunner.Run(context.Background(), model.CommandRequest{Name: "ls", Args: []string{"/definitely/missing"}})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.ExitCode == 0 {
		t.Fatalf("expected non-zero exit code, got %d", result.ExitCode)
	}
	if !result.Truncated {
		t.Fatalf("expected truncation for bounded stderr/stdout, got %+v", result)
	}
}

func TestCaptureBufferBranches(t *testing.T) {
	t.Parallel()

	zero := newCaptureBuffer(0)
	if _, err := zero.Write([]byte("demo")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if !zero.Truncated() {
		t.Fatal("expected zero-limit buffer to truncate")
	}

	buffer := newCaptureBuffer(3)
	if _, err := buffer.Write([]byte("abcd")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if buffer.String() != "abc" {
		t.Fatalf("expected truncated buffer, got %q", buffer.String())
	}

	if _, err := buffer.Write([]byte("z")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if !buffer.Truncated() {
		t.Fatal("expected full buffer to stay truncated")
	}
}

func TestIsPathArgument(t *testing.T) {
	t.Parallel()

	if !isPathArgument("/tmp/demo") || !isPathArgument("./demo") || !isPathArgument("../demo") {
		t.Fatal("expected path arguments to be detected")
	}
	if isPathArgument("demo") {
		t.Fatal("expected plain value not to be treated as path")
	}
}
