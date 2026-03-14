package tui

import "testing"

func TestViewIDConstants(t *testing.T) {
	if ViewScan != 0 {
		t.Errorf("ViewScan = %d, want 0", ViewScan)
	}
	if ViewResults != 1 {
		t.Errorf("ViewResults = %d, want 1", ViewResults)
	}
}

func TestSwitchViewMsgCarriesView(t *testing.T) {
	msg := switchViewMsg{view: ViewResults}
	if msg.view != ViewResults {
		t.Errorf("msg.view = %d, want ViewResults", msg.view)
	}
}

func TestDefaultKeyMapBindings(t *testing.T) {
	km := DefaultKeyMap()

	if len(km.ShortHelp()) == 0 {
		t.Error("ShortHelp should return bindings")
	}
	groups := km.FullHelp()
	if len(groups) != 3 {
		t.Errorf("FullHelp groups = %d, want 3", len(groups))
	}
}
