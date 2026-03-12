package checks_test

import (
	"context"
	"testing"

	"github.com/nagi1/larainspect/internal/checks"
	"github.com/nagi1/larainspect/internal/model"
)

type testCheck struct {
	id string
}

func (check testCheck) ID() string {
	return check.id
}

func (check testCheck) Run(context.Context, model.ExecutionContext, model.Snapshot) (model.CheckResult, error) {
	return model.CheckResult{}, nil
}

func TestRegistryRejectsDuplicateCheckIDs(t *testing.T) {
	t.Parallel()

	registry := checks.NewRegistry()
	if err := registry.Register(testCheck{id: "demo"}); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	if err := registry.Register(testCheck{id: "demo"}); err == nil {
		t.Fatal("expected duplicate registration error")
	}
}

func TestRegistryReturnsChecksInStableOrder(t *testing.T) {
	t.Parallel()

	registry := checks.NewRegistry()
	registry.MustRegister(testCheck{id: "zeta"})
	registry.MustRegister(testCheck{id: "alpha"})

	registered := registry.All()
	if len(registered) != 2 {
		t.Fatalf("expected 2 checks, got %d", len(registered))
	}

	if registered[0].ID() != "alpha" || registered[1].ID() != "zeta" {
		t.Fatalf("unexpected check order: %s, %s", registered[0].ID(), registered[1].ID())
	}
}
