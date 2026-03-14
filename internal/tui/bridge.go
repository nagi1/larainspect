package tui

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/nagi1/larainspect/internal/progress"
)

// BusEventMsg wraps a progress.Event as a bubbletea message.
type BusEventMsg struct {
	Event progress.Event
}

// Bridge forwards progress.Bus events into a Bubble Tea program.
type Bridge struct {
	bus     *progress.Bus
	program *tea.Program
}

// NewBridge creates a bridge between a progress.Bus and a tea.Program.
func NewBridge(bus *progress.Bus, program *tea.Program) *Bridge {
	return &Bridge{bus: bus, program: program}
}

// Start begins forwarding all events into the Bubble Tea program.
func (b *Bridge) Start() {
	b.bus.SubscribeAll(func(event progress.Event) {
		b.program.Send(BusEventMsg{Event: event})
	})
}

// Stop closes the event bus.
func (b *Bridge) Stop() {
	b.bus.Close()
}
