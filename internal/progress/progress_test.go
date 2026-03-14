package progress

import "testing"

func TestStageLabelAndOrder(t *testing.T) {
	t.Parallel()

	testCases := map[Stage]string{
		StageSetup:       "Setup",
		StageDiscovery:   "Discovery",
		StageChecks:      "Checks",
		StageCorrelation: "Correlation",
		StagePostProcess: "Post-Process",
		StageReport:      "Report",
		Stage("custom"):  "custom",
	}

	for stage, want := range testCases {
		if got := stage.Label(); got != want {
			t.Fatalf("%q.Label() = %q, want %q", stage, got, want)
		}
	}

	ordered := OrderedStages()
	if len(ordered) != 6 {
		t.Fatalf("expected 6 ordered stages, got %d", len(ordered))
	}

	if ordered[0] != StageSetup || ordered[len(ordered)-1] != StageReport {
		t.Fatalf("unexpected ordered stages %+v", ordered)
	}
}

func TestBusPublishRoutesHandlers(t *testing.T) {
	t.Parallel()

	bus := NewBus()
	events := []EventType{}

	bus.SubscribeAll(func(event Event) {
		events = append(events, event.Type)
	})

	bus.Subscribe(EventStageStarted, func(event Event) {
		events = append(events, EventType(string(event.Type)+"#specific"))
	})

	bus.Publish(NewEvent(EventStageStarted))
	bus.Close()
	bus.Publish(NewEvent(EventStageCompleted))

	if len(events) != 2 {
		t.Fatalf("expected 2 events before close, got %d", len(events))
	}

	if events[0] != EventStageStarted || events[1] != EventType("stage.started#specific") {
		t.Fatalf("unexpected routed events %+v", events)
	}
}

func TestBusNilAndGuardBranches(t *testing.T) {
	t.Parallel()

	var nilBus *Bus
	nilBus.Subscribe(EventStageStarted, nil)
	nilBus.SubscribeAll(nil)
	nilBus.Publish(NewEvent(EventStageCompleted))
	nilBus.Close()

	bus := NewBus()
	bus.Subscribe(EventStageStarted, nil)
	bus.SubscribeAll(nil)

	received := []EventType{}
	bus.SubscribeAll(func(event Event) {
		received = append(received, event.Type)
	})
	bus.Publish(Event{Type: EventStageCompleted})

	if len(received) != 1 || received[0] != EventStageCompleted {
		t.Fatalf("unexpected received events %+v", received)
	}
}
