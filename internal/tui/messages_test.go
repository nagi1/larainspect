package tui

import (
	"testing"

	"github.com/charmbracelet/bubbles/key"
)

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
	if !key.Matches(teaKey("left"), km.PanHorizontal) || !key.Matches(teaKey("home"), km.JumpHorizontal) {
		t.Error("keymap should advertise horizontal pan bindings")
	}
	if !key.Matches(teaKey("c"), km.Copy) || !key.Matches(teaKey("y"), km.Copy) {
		t.Error("keymap should advertise copy-detail bindings")
	}
}

func teaKey(keyName string) keyEventLike {
	return keyEventLike{keyName: keyName}
}

type keyEventLike struct {
	keyName string
}

func (k keyEventLike) String() string {
	return k.keyName
}
