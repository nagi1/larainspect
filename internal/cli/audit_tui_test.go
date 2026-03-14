package cli

import (
	"bytes"
	"testing"

	"github.com/nagi1/larainspect/internal/model"
)

func TestShouldUseTUIScreenReader(t *testing.T) {
	cfg := model.AuditConfig{
		Format:       model.OutputFormatTerminal,
		ScreenReader: true,
	}
	if shouldUseTUIWithTerminalCheck(fakeTTYReader{}, fakeTTYWriter{}, cfg, alwaysTerminal) {
		t.Error("shouldUseTUI should return false for screen reader mode")
	}
}

func TestShouldUseTUIQuietMode(t *testing.T) {
	cfg := model.AuditConfig{
		Format:    model.OutputFormatTerminal,
		Verbosity: model.VerbosityQuiet,
	}
	if shouldUseTUIWithTerminalCheck(fakeTTYReader{}, fakeTTYWriter{}, cfg, alwaysTerminal) {
		t.Error("shouldUseTUI should return false for quiet mode")
	}
}

func TestShouldUseTUIJSONFormat(t *testing.T) {
	cfg := model.AuditConfig{
		Format: model.OutputFormatJSON,
	}
	if shouldUseTUIWithTerminalCheck(fakeTTYReader{}, fakeTTYWriter{}, cfg, alwaysTerminal) {
		t.Error("shouldUseTUI should return false for JSON output")
	}
}

func TestShouldUseTUIColorModeNever(t *testing.T) {
	cfg := model.AuditConfig{
		Format:    model.OutputFormatTerminal,
		ColorMode: model.ColorModeNever,
	}
	if shouldUseTUIWithTerminalCheck(fakeTTYReader{}, fakeTTYWriter{}, cfg, alwaysTerminal) {
		t.Error("shouldUseTUI should return false for color mode never")
	}
}

func TestShouldUseTUIMarkdownFormat(t *testing.T) {
	cfg := model.AuditConfig{
		Format: model.OutputFormatMarkdown,
	}
	if shouldUseTUIWithTerminalCheck(fakeTTYReader{}, fakeTTYWriter{}, cfg, alwaysTerminal) {
		t.Error("shouldUseTUI should return false for markdown format")
	}
}

func TestShouldUseTUIRequiresTerminalInputAndOutput(t *testing.T) {
	cfg := model.AuditConfig{
		Format:    model.OutputFormatTerminal,
		Verbosity: model.VerbosityNormal,
		ColorMode: model.ColorModeAuto,
	}

	if !shouldUseTUIWithTerminalCheck(fakeTTYReader{}, fakeTTYWriter{}, cfg, alwaysTerminal) {
		t.Fatal("shouldUseTUI should return true when stdin and stdout are terminals")
	}

	if shouldUseTUIWithTerminalCheck(bytes.NewBuffer(nil), fakeTTYWriter{}, cfg, alwaysTerminal) {
		t.Fatal("shouldUseTUI should return false when stdin is not a terminal-backed reader")
	}

	if shouldUseTUIWithTerminalCheck(fakeTTYReader{}, bytes.NewBuffer(nil), cfg, alwaysTerminal) {
		t.Fatal("shouldUseTUI should return false when stdout is not a terminal-backed writer")
	}
}

type fakeTTYReader struct{}

func (fakeTTYReader) Read(p []byte) (int, error) { return 0, nil }
func (fakeTTYReader) Fd() uintptr                { return 0 }

type fakeTTYWriter struct{}

func (fakeTTYWriter) Write(p []byte) (int, error) { return len(p), nil }
func (fakeTTYWriter) Fd() uintptr                 { return 1 }

func alwaysTerminal(uintptr) bool { return true }
