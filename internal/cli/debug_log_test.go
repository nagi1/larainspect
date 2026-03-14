package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nagi1/larainspect/internal/debuglog"
	"github.com/nagi1/larainspect/internal/model"
	"github.com/nagi1/larainspect/internal/progress"
)

type commandLogRecorder struct {
	calls   int
	results []model.CommandResult
	errs    []error
}

func (recorder *commandLogRecorder) LogCommand(result model.CommandResult, err error) {
	recorder.calls++
	recorder.results = append(recorder.results, result)
	recorder.errs = append(recorder.errs, err)
}

func TestOpenDebugLoggerDisabled(t *testing.T) {
	t.Parallel()

	logger, closeLogger, err := openDebugLogger(model.AuditConfig{})
	if err != nil {
		t.Fatalf("openDebugLogger() error = %v", err)
	}
	defer closeLogger()

	if logger != nil {
		t.Fatal("expected nil logger when debug log path is empty")
	}
}

func TestOpenDebugLoggerCreatesFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "larainspect-debug.log")
	logger, closeLogger, err := openDebugLogger(model.AuditConfig{DebugLogPath: path})
	if err != nil {
		t.Fatalf("openDebugLogger() error = %v", err)
	}

	logger.LogProgressEvent(progress.Event{
		Type:    progress.EventAuditStarted,
		Message: "starting",
	})
	closeLogger()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if !strings.Contains(string(data), `type="audit.started"`) {
		t.Fatalf("expected progress event in debug log, got %q", string(data))
	}
}

func TestOpenDebugLoggerIncludesPathInError(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "missing", "larainspect-debug.log")
	_, closeLogger, err := openDebugLogger(model.AuditConfig{DebugLogPath: path})
	defer closeLogger()
	if err == nil {
		t.Fatal("expected openDebugLogger() to fail for missing directory")
	}
	if !strings.Contains(err.Error(), path) {
		t.Fatalf("expected error to mention path, got %v", err)
	}
}

func TestAttachDebugLoggerPublishesEvents(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	logger := debuglog.New(&out)
	bus := progress.NewBus()
	attachDebugLogger(bus, logger)

	bus.Publish(progress.Event{Type: progress.EventStageStarted, Message: "stage started"})

	if !strings.Contains(out.String(), `type="stage.started"`) {
		t.Fatalf("expected attached logger to receive progress events, got %q", out.String())
	}
}

func TestAttachDebugLoggerIgnoresNilInputs(t *testing.T) {
	t.Parallel()

	attachDebugLogger(nil, nil)
	attachDebugLogger(progress.NewBus(), nil)
}

func TestNewExecutionContextAttachesCommandLogger(t *testing.T) {
	t.Parallel()

	recorder := &commandLogRecorder{}
	execution, err := newExecutionContext(model.DefaultAuditConfig(), recorder)
	if err != nil {
		t.Fatalf("newExecutionContext() error = %v", err)
	}

	if _, err := execution.Commands.Run(context.Background(), model.CommandRequest{Name: "pwd"}); err != nil {
		t.Fatalf("Commands.Run() error = %v", err)
	}

	if recorder.calls != 1 {
		t.Fatalf("expected command logger to be called once, got %d", recorder.calls)
	}
	if recorder.results[0].Command.Name != "pwd" {
		t.Fatalf("expected logged command to be pwd, got %q", recorder.results[0].Command.Name)
	}
}

func TestNoopReporter(t *testing.T) {
	t.Parallel()

	reporter := noopReporter{}
	if reporter.Format() != "tui" {
		t.Fatalf("Format() = %q, want tui", reporter.Format())
	}
	if err := reporter.Render(&bytes.Buffer{}, model.Report{}); err != nil {
		t.Fatalf("Render() error = %v", err)
	}
}

func TestBuildTUIOutputsWithArtifacts(t *testing.T) {
	t.Parallel()

	reportPath := filepath.Join(t.TempDir(), "report.json")
	outputs, closeOutputs, err := buildTUIOutputs(model.AuditConfig{ReportJSONPath: reportPath})
	if err != nil {
		t.Fatalf("buildTUIOutputs() error = %v", err)
	}
	defer closeOutputs()

	if len(outputs) != 2 {
		t.Fatalf("expected noop + json outputs, got %d", len(outputs))
	}
	if outputs[0].Reporter.Format() != "tui" {
		t.Fatalf("unexpected first output format %q", outputs[0].Reporter.Format())
	}
	if outputs[1].Reporter.Format() != model.OutputFormatJSON {
		t.Fatalf("unexpected second output format %q", outputs[1].Reporter.Format())
	}
}

func TestExecuteAuditWithConfigDebugLogOpenFailure(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := executeAuditWithConfig(context.Background(), strings.NewReader(""), &stdout, &stderr, model.AuditConfig{
		Format:       model.OutputFormatJSON,
		Verbosity:    model.VerbosityQuiet,
		DebugLogPath: filepath.Join(t.TempDir(), "missing", "larainspect-debug.log"),
	})

	if exitCode != int(model.ExitCodeAuditFailed) {
		t.Fatalf("expected audit failed exit code, got %d stderr=%q", exitCode, stderr.String())
	}
	if !strings.Contains(stderr.String(), "open debug log") {
		t.Fatalf("expected debug log open error, got %q", stderr.String())
	}
}

func TestExecuteAuditWithTUIBuildOutputFailure(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := executeAuditWithTUI(
		context.Background(),
		strings.NewReader("q"),
		&stdout,
		&stderr,
		model.AuditConfig{
			Format:         model.OutputFormatTerminal,
			Verbosity:      model.VerbosityNormal,
			ReportJSONPath: "/dev/null/nonexistent/report.json",
		},
		nil,
	)

	if exitCode != int(model.ExitCodeAuditFailed) {
		t.Fatalf("expected audit failed exit code, got %d stderr=%q", exitCode, stderr.String())
	}
}
