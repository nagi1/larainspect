package tui

import "github.com/charmbracelet/bubbles/key"

// KeyMap defines all key bindings for the application.
type KeyMap struct {
	Quit           key.Binding
	Help           key.Binding
	Up             key.Binding
	Down           key.Binding
	PanHorizontal  key.Binding
	JumpHorizontal key.Binding
	Enter          key.Binding
	Tab            key.Binding
	Escape         key.Binding
	SortFindings   key.Binding
	ScrollUp       key.Binding
	ScrollDown     key.Binding
}

// DefaultKeyMap returns the default key bindings.
func DefaultKeyMap() KeyMap {
	return KeyMap{
		Quit: key.NewBinding(
			key.WithKeys("q", "ctrl+c"),
			key.WithHelp("q", "quit"),
		),
		Help: key.NewBinding(
			key.WithKeys("?"),
			key.WithHelp("?", "help"),
		),
		Up: key.NewBinding(
			key.WithKeys("up", "k"),
			key.WithHelp("k/↑", "move up"),
		),
		Down: key.NewBinding(
			key.WithKeys("down", "j"),
			key.WithHelp("j/↓", "move down"),
		),
		PanHorizontal: key.NewBinding(
			key.WithKeys("left", "right"),
			key.WithHelp("←/→", "pan focused"),
		),
		JumpHorizontal: key.NewBinding(
			key.WithKeys("home", "end"),
			key.WithHelp("home/end", "jump pan"),
		),
		Enter: key.NewBinding(
			key.WithKeys("enter"),
			key.WithHelp("enter", "select"),
		),
		Tab: key.NewBinding(
			key.WithKeys("tab"),
			key.WithHelp("tab", "switch panel"),
		),
		Escape: key.NewBinding(
			key.WithKeys("esc"),
			key.WithHelp("esc", "back"),
		),
		SortFindings: key.NewBinding(
			key.WithKeys("s"),
			key.WithHelp("s", "cycle sort"),
		),
		ScrollUp: key.NewBinding(
			key.WithKeys("pgup"),
			key.WithHelp("pgup", "scroll up"),
		),
		ScrollDown: key.NewBinding(
			key.WithKeys("pgdown"),
			key.WithHelp("pgdown", "scroll down"),
		),
	}
}

// ShortHelp returns bindings for the compact help view.
func (k KeyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Help, k.Quit, k.Tab, k.Up, k.PanHorizontal}
}

// FullHelp returns all bindings for the expanded help view.
func (k KeyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.Up, k.Down, k.PanHorizontal, k.JumpHorizontal},
		{k.Enter, k.Escape, k.Tab, k.SortFindings},
		{k.ScrollUp, k.ScrollDown, k.Help, k.Quit},
	}
}
