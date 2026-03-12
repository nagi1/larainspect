package checks

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/nagi/larainspect/internal/model"
)

type Check interface {
	ID() string
	Run(context.Context, model.ExecutionContext, model.Snapshot) (model.CheckResult, error)
}

type Registry struct {
	mu     sync.RWMutex
	checks map[string]Check
}

func NewRegistry() *Registry {
	return &Registry{
		checks: map[string]Check{},
	}
}

func (registry *Registry) Register(check Check) error {
	registry.mu.Lock()
	defer registry.mu.Unlock()

	id := check.ID()
	if _, exists := registry.checks[id]; exists {
		return fmt.Errorf("check %q already registered", id)
	}

	registry.checks[id] = check
	return nil
}

func (registry *Registry) MustRegister(check Check) {
	if err := registry.Register(check); err != nil {
		panic(err)
	}
}

func (registry *Registry) All() []Check {
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	ids := make([]string, 0, len(registry.checks))
	for id := range registry.checks {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	ordered := make([]Check, 0, len(ids))
	for _, id := range ids {
		ordered = append(ordered, registry.checks[id])
	}

	return ordered
}

var defaultRegistry = NewRegistry()

func Register(check Check) error {
	return defaultRegistry.Register(check)
}

func MustRegister(check Check) {
	defaultRegistry.MustRegister(check)
}

func Registered() []Check {
	return defaultRegistry.All()
}
