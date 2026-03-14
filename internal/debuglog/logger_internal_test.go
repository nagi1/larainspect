package debuglog

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nagi1/larainspect/internal/model"
	"github.com/nagi1/larainspect/internal/progress"
)

func TestOpenFileWritesLogs(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "debug.log")
	logger, closer, err := OpenFile(path)
	if err != nil {
		t.Fatalf("OpenFile() error = %v", err)
	}

	logger.LogProgressEvent(progress.Event{Type: progress.EventAuditStarted})
	_ = closer.Close()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if !strings.Contains(string(data), "progress") {
		t.Fatalf("expected progress log entry, got %q", string(data))
	}
}

func TestLoggerNilSafe(t *testing.T) {
	t.Parallel()

	var logger *Logger
	logger.LogProgressEvent(progress.Event{})
	logger.LogCommand(model.CommandResult{}, nil)
}

func TestFieldHelpers(t *testing.T) {
	t.Parallel()

	if got := field("message", "  hello world  "); got != `message="hello world"` {
		t.Fatalf("field() = %q", got)
	}
	if got := field("message", "   "); got != "" {
		t.Fatalf("field() empty = %q", got)
	}
	if got := intField("count", 2); got != "count=2" {
		t.Fatalf("intField() = %q", got)
	}
	if got := boolField("ok", true); got != "ok=true" {
		t.Fatalf("boolField() = %q", got)
	}
	if got := errorField("err", errors.New("boom")); got != `err="boom"` {
		t.Fatalf("errorField() = %q", got)
	}
	if got := errorField("err", nil); got != "" {
		t.Fatalf("errorField(nil) = %q", got)
	}
}

func TestCompact(t *testing.T) {
	t.Parallel()

	if got := compact(" a\n\tb  c "); got != "a b c" {
		t.Fatalf("compact() = %q", got)
	}
	if got := compact("   "); got != "" {
		t.Fatalf("compact() empty = %q", got)
	}
}
