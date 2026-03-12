package checks

import (
	"context"
	"testing"

	"github.com/nagi1/larainspect/internal/model"
)

func TestPackageLevelRegistryHelpers(t *testing.T) {
	original := defaultRegistry
	defaultRegistry = NewRegistry()
	t.Cleanup(func() {
		defaultRegistry = original
	})

	if err := Register(testCheckAdapter{id: "alpha"}); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	MustRegister(testCheckAdapter{id: "beta"})

	registered := Registered()
	if len(registered) != 2 {
		t.Fatalf("expected 2 registered checks, got %d", len(registered))
	}
}

func TestRegistryMustRegisterPanicsOnDuplicate(t *testing.T) {
	registry := NewRegistry()
	registry.MustRegister(testCheckAdapter{id: "dup"})

	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on duplicate must register")
		}
	}()

	registry.MustRegister(testCheckAdapter{id: "dup"})
}

type testCheckAdapter struct {
	id string
}

func (check testCheckAdapter) ID() string { return check.id }

func (check testCheckAdapter) Run(context.Context, model.ExecutionContext, model.Snapshot) (model.CheckResult, error) {
	return model.CheckResult{}, nil
}
