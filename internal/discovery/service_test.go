package discovery_test

import (
	"context"
	"testing"

	"github.com/nagi/larainspect/internal/discovery"
	"github.com/nagi/larainspect/internal/model"
)

func TestNoopServiceReturnsHostAndTools(t *testing.T) {
	t.Parallel()

	execution := model.ExecutionContext{
		Host:  model.Host{Hostname: "demo"},
		Tools: model.ToolAvailability{"stat": true},
	}

	snapshot, unknowns, err := discovery.NoopService{}.Discover(context.Background(), execution)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}

	if len(unknowns) != 0 {
		t.Fatalf("expected no unknowns, got %d", len(unknowns))
	}

	if snapshot.Host.Hostname != "demo" || !snapshot.Tools["stat"] {
		t.Fatalf("unexpected snapshot: %+v", snapshot)
	}
}
