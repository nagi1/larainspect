package tui

import (
	"testing"

	"github.com/nagi1/larainspect/internal/progress"
)

func TestBridgeForwardsEvents(t *testing.T) {
	// Bridge is a thin wrapper — test that construction works and Stop doesn't panic.
	bus := progress.NewBus()
	defer bus.Close()

	bridge := NewBridge(bus, nil)
	if bridge == nil {
		t.Fatal("NewBridge returned nil")
	}
	if bridge.bus != bus {
		t.Error("bridge should reference the provided bus")
	}
}

func TestBusEventMsgWrapsEvent(t *testing.T) {
	event := progress.Event{Type: progress.EventAuditStarted, ComponentID: "test"}
	msg := BusEventMsg{Event: event}

	if msg.Event.Type != progress.EventAuditStarted {
		t.Errorf("BusEventMsg.Event.Type = %q, want EventAuditStarted", msg.Event.Type)
	}
	if msg.Event.ComponentID != "test" {
		t.Errorf("BusEventMsg.Event.ComponentID = %q, want %q", msg.Event.ComponentID, "test")
	}
}
