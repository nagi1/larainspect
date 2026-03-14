package progress

import (
	"errors"
	"testing"

	"github.com/nagi1/larainspect/internal/model"
)

func TestStateTracksChecksCorrelatorsAndRecentEvents(t *testing.T) {
	t.Parallel()

	state := NewState(3)
	state.Handle(Event{Type: EventStageStarted, Stage: StageDiscovery})
	state.Handle(Event{Type: EventContextResolved, AppCount: 1, AppName: "acme/shop", LaravelVersion: "v11.9.0", PHPVersion: "^8.2", PackageCount: 3, SourceMatches: 2, ArtifactCount: 1})
	state.Handle(Event{Type: EventCheckRegistered, ComponentID: "check.one", Message: "first check", Total: 2})
	state.Handle(Event{Type: EventCheckRegistered, ComponentID: "check.two", Message: "second check", Total: 2})
	state.Handle(Event{Type: EventCheckStarted, ComponentID: "check.one", Completed: 0, Total: 2})
	state.Handle(Event{Type: EventFindingDiscovered, Severity: model.SeverityHigh})
	state.Handle(Event{Type: EventUnknownObserved, ErrorKind: model.ErrorKindPermissionDenied})
	state.Handle(Event{Type: EventCheckCompleted, ComponentID: "check.one", Findings: 2, Unknowns: 1, Completed: 1, Total: 2})
	state.Handle(Event{Type: EventCheckFailed, ComponentID: "check.two", Err: errors.New("boom"), Completed: 2, Total: 2})
	state.Handle(Event{Type: EventCorrelatorRegistered, ComponentID: "corr.one", Total: 1})
	state.Handle(Event{Type: EventCorrelatorCompleted, ComponentID: "corr.one", Findings: 1, Completed: 1, Total: 1})

	snapshot := state.Snapshot()

	if snapshot.CurrentStage != StageDiscovery {
		t.Fatalf("CurrentStage = %q", snapshot.CurrentStage)
	}
	if snapshot.Context.AppName != "acme/shop" || snapshot.Context.LaravelVersion != "v11.9.0" || snapshot.Context.PHPVersion != "^8.2" {
		t.Fatalf("unexpected context %+v", snapshot.Context)
	}
	if snapshot.CheckTotal != 2 || snapshot.CheckCompleted != 2 {
		t.Fatalf("unexpected check progress %+v", snapshot)
	}
	if snapshot.CorrelatorTotal != 1 || snapshot.CorrelatorCompleted != 1 {
		t.Fatalf("unexpected correlator progress %+v", snapshot)
	}
	if snapshot.FindingsDiscovered != 1 || snapshot.UnknownsObserved != 1 {
		t.Fatalf("unexpected live totals %+v", snapshot)
	}
	if snapshot.SeverityCounts[model.SeverityHigh] != 1 {
		t.Fatalf("unexpected severity counts %+v", snapshot.SeverityCounts)
	}
	if len(snapshot.Checks) != 2 || snapshot.Checks[0].Status != ComponentStatusCompleted || snapshot.Checks[1].Status != ComponentStatusFailed {
		t.Fatalf("unexpected checks %+v", snapshot.Checks)
	}
	if snapshot.Checks[0].Description != "first check" || snapshot.Checks[1].Description != "second check" {
		t.Fatalf("unexpected descriptions %+v", snapshot.Checks)
	}
	if len(snapshot.Correlators) != 1 || snapshot.Correlators[0].ID != "corr.one" {
		t.Fatalf("unexpected correlators %+v", snapshot.Correlators)
	}
	if len(snapshot.RecentEvents) != 3 {
		t.Fatalf("expected capped recent events, got %d", len(snapshot.RecentEvents))
	}
	if snapshot.RecentEvents[0].Type != EventCheckFailed || snapshot.RecentEvents[1].Type != EventCorrelatorRegistered || snapshot.RecentEvents[2].Type != EventCorrelatorCompleted {
		t.Fatalf("unexpected recent events %+v", snapshot.RecentEvents)
	}
}

func TestStateNilBranches(t *testing.T) {
	t.Parallel()

	var state *State
	state.Handle(Event{Type: EventStageCompleted})

	if snapshot := state.Snapshot(); snapshot.CurrentStage != "" || len(snapshot.RecentEvents) != 0 {
		t.Fatalf("unexpected nil snapshot %+v", snapshot)
	}
}

func TestNewStateAppliesDefaultRecentEventCap(t *testing.T) {
	t.Parallel()

	state := NewState(0)
	if state.maxRecentEvents != 50 {
		t.Fatalf("expected default recent event cap, got %d", state.maxRecentEvents)
	}
}
