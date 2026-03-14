package runner_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nagi1/larainspect/internal/model"
	"github.com/nagi1/larainspect/internal/runner"
)

func TestCommandRunnerRejectsUnknownCommands(t *testing.T) {
	t.Parallel()

	commandRunner := runner.NewCommandRunner(time.Second, 1024, runner.DefaultAllowlist())

	_, err := commandRunner.Run(context.Background(), model.CommandRequest{Name: "rm", Args: []string{"-rf", "/"}})
	if !errors.Is(err, runner.ErrCommandRejected) {
		t.Fatalf("expected ErrCommandRejected, got %v", err)
	}
}

func TestCommandRunnerCapturesCommandOutput(t *testing.T) {
	t.Parallel()

	commandRunner := runner.NewCommandRunner(time.Second, 1024, runner.NewAllowlist([]runner.Specification{
		{Name: "pwd", MaxArgs: 0},
	}))

	result, err := commandRunner.Run(context.Background(), model.CommandRequest{Name: "pwd"})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.ExitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", result.ExitCode)
	}

	if !strings.Contains(result.Stdout, "larainspect") {
		t.Fatalf("expected pwd output to contain workspace path, got %q", result.Stdout)
	}
}

func TestCommandRunnerTimesOutLongRunningCommands(t *testing.T) {
	t.Parallel()

	commandRunner := runner.NewCommandRunner(50*time.Millisecond, 1024, runner.NewAllowlist([]runner.Specification{
		{Name: "sleep", AllowValues: true, MaxArgs: 1},
	}))

	_, err := commandRunner.Run(context.Background(), model.CommandRequest{Name: "sleep", Args: []string{"1"}})
	if !errors.Is(err, runner.ErrCommandTimedOut) {
		t.Fatalf("expected ErrCommandTimedOut, got %v", err)
	}
}

func TestCommandRunnerNotifiesObserver(t *testing.T) {
	t.Parallel()

	commandRunner := runner.NewCommandRunner(time.Second, 1024, runner.NewAllowlist([]runner.Specification{
		{Name: "pwd", MaxArgs: 0},
	}))

	called := false
	commandRunner.SetObserver(func(result model.CommandResult, err error) {
		called = true
		if err != nil {
			t.Fatalf("observer err = %v", err)
		}
		if result.Command.Name != "pwd" {
			t.Fatalf("observer command = %q", result.Command.Name)
		}
	})

	if _, err := commandRunner.Run(context.Background(), model.CommandRequest{Name: "pwd"}); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if !called {
		t.Fatal("expected observer to be called")
	}
}
