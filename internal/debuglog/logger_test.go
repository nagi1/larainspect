package debuglog_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nagi1/larainspect/internal/debuglog"
	"github.com/nagi1/larainspect/internal/model"
	"github.com/nagi1/larainspect/internal/progress"
)

func TestLoggerLogProgressEvent(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	logger := debuglog.New(&out)

	logger.LogProgressEvent(progress.Event{
		Type:        progress.EventStageStarted,
		Stage:       progress.StageDiscovery,
		Message:     "collecting host and Laravel evidence",
		ComponentID: "discovery",
		At:          time.Unix(0, 0).UTC(),
	})

	got := out.String()
	if !strings.Contains(got, "progress") || !strings.Contains(got, `type="stage.started"`) || !strings.Contains(got, `message="collecting host and Laravel evidence"`) {
		t.Fatalf("unexpected progress log output %q", got)
	}
}

func TestLoggerLogCommand(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	logger := debuglog.New(&out)

	logger.LogCommand(model.CommandResult{
		Command:    model.CommandRequest{Name: "pwd"},
		ExitCode:   0,
		Duration:   "1ms",
		Stdout:     "/srv/app\n",
		StartedAt:  time.Unix(0, 0).UTC(),
		FinishedAt: time.Unix(1, 0).UTC(),
	}, errors.New("boom"))

	got := out.String()
	if !strings.Contains(got, "command") || !strings.Contains(got, `name="pwd"`) || !strings.Contains(got, `stdout="/srv/app"`) || !strings.Contains(got, `err="boom"`) {
		t.Fatalf("unexpected command log output %q", got)
	}
}
