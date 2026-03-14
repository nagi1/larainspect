package orchestrator_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nagi1/larainspect/internal/baseline"
	"github.com/nagi1/larainspect/internal/checks"
	"github.com/nagi1/larainspect/internal/correlators"
	"github.com/nagi1/larainspect/internal/discovery"
	"github.com/nagi1/larainspect/internal/model"
	"github.com/nagi1/larainspect/internal/orchestrator"
	"github.com/nagi1/larainspect/internal/progress"
	"github.com/nagi1/larainspect/internal/runner"
	"github.com/nagi1/larainspect/internal/store"
)

func TestOrchestratorRunsAuditAndRendersReport(t *testing.T) {
	t.Parallel()

	execution, err := runner.NewExecutionContext(model.AuditConfig{}, stubExecutor{})
	if err != nil {
		t.Fatalf("NewExecutionContext() error = %v", err)
	}

	var output bytes.Buffer
	progressBus := progress.NewBus()
	eventTypes := []progress.EventType{}
	progressBus.SubscribeAll(func(event progress.Event) {
		eventTypes = append(eventTypes, event.Type)
	})

	reportData, err := orchestrator.Orchestrator{
		Execution: execution,
		Discovery: discovery.NoopService{},
		Checks: []checks.Check{
			stubCheck{
				id: "checks.demo",
				result: model.CheckResult{
					Findings: []model.Finding{sampleFinding("checks.demo", model.FindingClassDirect, model.SeverityHigh)},
				},
			},
		},
		Correlators: []correlators.Correlator{
			stubCorrelator{id: "correlation.demo"},
		},
		Outputs: []orchestrator.Output{
			{Reporter: stubReporter{format: "terminal"}, Writer: &output},
		},
		ProgressBus: progressBus,
	}.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if reportData.Summary.TotalFindings != 1 {
		t.Fatalf("expected 1 finding, got %d", reportData.Summary.TotalFindings)
	}

	if !strings.Contains(output.String(), "findings=1 unknowns=0") {
		t.Fatalf("expected rendered output, got %q", output.String())
	}

	for _, want := range []progress.EventType{
		progress.EventAuditStarted,
		progress.EventStageStarted,
		progress.EventStageCompleted,
		progress.EventContextResolved,
		progress.EventCheckCompleted,
		progress.EventCorrelatorCompleted,
		progress.EventAuditCompleted,
	} {
		if !slices.Contains(eventTypes, want) {
			t.Fatalf("expected event %q in %+v", want, eventTypes)
		}
	}
}

func TestOrchestratorAppliesBaselineBeforeRendering(t *testing.T) {
	t.Parallel()

	execution, err := runner.NewExecutionContext(model.AuditConfig{}, stubExecutor{})
	if err != nil {
		t.Fatalf("NewExecutionContext() error = %v", err)
	}

	finding := sampleFinding("checks.demo", model.FindingClassDirect, model.SeverityHigh)
	baselinePath := filepath.Join(t.TempDir(), "audit-baseline.json")
	if err := baseline.Save(baselinePath, []model.Finding{finding}); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	execution.Config.BaselinePath = baselinePath

	var output bytes.Buffer
	var events []progress.Event
	progressBus := progress.NewBus()
	progressBus.SubscribeAll(func(event progress.Event) {
		events = append(events, event)
	})

	reportData, err := orchestrator.Orchestrator{
		Execution: execution,
		Discovery: discovery.NoopService{},
		Checks: []checks.Check{
			stubCheck{
				id: "checks.demo",
				result: model.CheckResult{
					Findings: []model.Finding{finding},
				},
			},
		},
		Outputs: []orchestrator.Output{
			{Reporter: stubReporter{format: "terminal"}, Writer: &output},
		},
		ProgressBus: progressBus,
	}.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if reportData.Summary.TotalFindings != 0 {
		t.Fatalf("expected suppressed report to be clean, got %+v", reportData.Summary)
	}

	if !strings.Contains(output.String(), "findings=0 unknowns=0") {
		t.Fatalf("expected rendered suppressed output, got %q", output.String())
	}

	postProcessCompleted := findEvent(events, progress.EventStageCompleted, progress.StagePostProcess)
	if !strings.Contains(postProcessCompleted.Message, "baseline_suppressed=1") {
		t.Fatalf("expected post-process baseline summary, got %+v", postProcessCompleted)
	}
}

func TestOrchestratorFailsAtPostProcessForInvalidBaseline(t *testing.T) {
	t.Parallel()

	execution, err := runner.NewExecutionContext(model.AuditConfig{}, stubExecutor{})
	if err != nil {
		t.Fatalf("NewExecutionContext() error = %v", err)
	}

	baselinePath := filepath.Join(t.TempDir(), "broken-baseline.json")
	if err := os.WriteFile(baselinePath, []byte("{"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	execution.Config.BaselinePath = baselinePath

	_, err = orchestrator.Orchestrator{
		Execution: execution,
		Discovery: discovery.NoopService{},
		Outputs: []orchestrator.Output{
			{Reporter: stubReporter{format: "terminal"}, Writer: &bytes.Buffer{}},
		},
	}.Run(context.Background())
	if err == nil {
		t.Fatal("expected post-process error")
	}

	if got := runner.StageForError(err); got != progress.StagePostProcess {
		t.Fatalf("StageForError() = %q", got)
	}
}

func TestOrchestratorSummarizesHistoryDiffDuringPostProcess(t *testing.T) {
	t.Parallel()

	execution, err := runner.NewExecutionContext(model.AuditConfig{}, stubExecutor{})
	if err != nil {
		t.Fatalf("NewExecutionContext() error = %v", err)
	}

	storeDir := t.TempDir()
	previousReport, err := model.BuildReport(
		execution.Host,
		time.Unix(1700000000, 0),
		time.Second,
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("BuildReport() error = %v", err)
	}
	if _, err := store.New(storeDir).Save(previousReport); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	execution.Config.StoreDir = storeDir

	var events []progress.Event
	progressBus := progress.NewBus()
	progressBus.SubscribeAll(func(event progress.Event) {
		events = append(events, event)
	})

	_, err = orchestrator.Orchestrator{
		Execution: execution,
		Discovery: discovery.NoopService{},
		Checks: []checks.Check{
			stubCheck{
				id: "checks.demo",
				result: model.CheckResult{
					Findings: []model.Finding{sampleFinding("checks.demo", model.FindingClassDirect, model.SeverityHigh)},
				},
			},
		},
		Outputs: []orchestrator.Output{
			{Reporter: stubReporter{format: "terminal"}, Writer: &bytes.Buffer{}},
		},
		ProgressBus: progressBus,
	}.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	postProcessCompleted := findEvent(events, progress.EventStageCompleted, progress.StagePostProcess)
	for _, want := range []string{"history_new=1", "history_resolved=0"} {
		if !strings.Contains(postProcessCompleted.Message, want) {
			t.Fatalf("expected post-process history summary to contain %q, got %+v", want, postProcessCompleted)
		}
	}
}

func TestOrchestratorWrapsReporterErrorsAtReportStage(t *testing.T) {
	t.Parallel()

	execution, err := runner.NewExecutionContext(model.AuditConfig{}, stubExecutor{})
	if err != nil {
		t.Fatalf("NewExecutionContext() error = %v", err)
	}

	_, err = orchestrator.Orchestrator{
		Execution: execution,
		Discovery: discovery.NoopService{},
		Outputs: []orchestrator.Output{
			{Reporter: stubReporter{format: "terminal", err: errors.New("render failed")}, Writer: &bytes.Buffer{}},
		},
	}.Run(context.Background())
	if err == nil {
		t.Fatal("expected report-stage error")
	}

	if got := runner.StageForError(err); got != progress.StageReport {
		t.Fatalf("StageForError() = %q", got)
	}
}

func TestOrchestratorRejectsMissingReportOutputs(t *testing.T) {
	t.Parallel()

	execution, err := runner.NewExecutionContext(model.AuditConfig{}, stubExecutor{})
	if err != nil {
		t.Fatalf("NewExecutionContext() error = %v", err)
	}

	_, err = orchestrator.Orchestrator{
		Execution: execution,
		Discovery: discovery.NoopService{},
	}.Run(context.Background())
	if !errors.Is(err, orchestrator.ErrMissingOutputs) {
		t.Fatalf("expected ErrMissingOutputs, got %v", err)
	}
}

func TestOrchestratorRejectsMissingDiscoveryService(t *testing.T) {
	t.Parallel()

	execution, err := runner.NewExecutionContext(model.AuditConfig{}, stubExecutor{})
	if err != nil {
		t.Fatalf("NewExecutionContext() error = %v", err)
	}

	_, err = orchestrator.Orchestrator{
		Execution: execution,
		Outputs: []orchestrator.Output{
			{Reporter: stubReporter{format: "terminal"}, Writer: &bytes.Buffer{}},
		},
	}.Run(context.Background())
	if !errors.Is(err, runner.ErrMissingDiscoveryService) {
		t.Fatalf("expected ErrMissingDiscoveryService, got %v", err)
	}
}

func TestOrchestratorRejectsMissingReporterAndWriter(t *testing.T) {
	t.Parallel()

	execution, err := runner.NewExecutionContext(model.AuditConfig{}, stubExecutor{})
	if err != nil {
		t.Fatalf("NewExecutionContext() error = %v", err)
	}

	_, err = orchestrator.Orchestrator{
		Execution: execution,
		Discovery: discovery.NoopService{},
		Outputs: []orchestrator.Output{
			{Writer: &bytes.Buffer{}},
		},
	}.Run(context.Background())
	if !errors.Is(err, orchestrator.ErrMissingReporter) {
		t.Fatalf("expected ErrMissingReporter, got %v", err)
	}

	_, err = orchestrator.Orchestrator{
		Execution: execution,
		Discovery: discovery.NoopService{},
		Outputs: []orchestrator.Output{
			{Reporter: stubReporter{format: ""}},
		},
	}.Run(context.Background())
	if !errors.Is(err, orchestrator.ErrMissingOutputWriter) {
		t.Fatalf("expected ErrMissingOutputWriter, got %v", err)
	}
}

type stubReporter struct {
	format string
	err    error
}

func (reporter stubReporter) Format() string {
	if reporter.format == "" {
		return "stub"
	}

	return reporter.format
}

func (reporter stubReporter) Render(writer io.Writer, reportData model.Report) error {
	if reporter.err != nil {
		return reporter.err
	}

	_, err := writer.Write([]byte(
		"findings=" + fmt.Sprint(reportData.Summary.TotalFindings) + " unknowns=" + fmt.Sprint(reportData.Summary.Unknowns),
	))
	return err
}

type stubExecutor struct{}

func (stubExecutor) Run(context.Context, model.CommandRequest) (model.CommandResult, error) {
	return model.CommandResult{
		ExitCode:   0,
		Duration:   time.Millisecond.String(),
		StartedAt:  time.Unix(1700000000, 0),
		FinishedAt: time.Unix(1700000000, int64(time.Millisecond)),
	}, nil
}

type stubCheck struct {
	id     string
	result model.CheckResult
	err    error
}

func (check stubCheck) ID() string {
	return check.id
}

func (check stubCheck) Description() string {
	return "stub check"
}

func (check stubCheck) Run(context.Context, model.ExecutionContext, model.Snapshot) (model.CheckResult, error) {
	return check.result, check.err
}

type stubCorrelator struct {
	id     string
	result model.CheckResult
	err    error
}

func (correlator stubCorrelator) ID() string {
	return correlator.id
}

func (correlator stubCorrelator) Description() string {
	return "stub correlator"
}

func (correlator stubCorrelator) Correlate(context.Context, model.ExecutionContext, model.Snapshot, []model.Finding) (model.CheckResult, error) {
	return correlator.result, correlator.err
}

func sampleFinding(checkID string, class model.FindingClass, severity model.Severity) model.Finding {
	return model.Finding{
		ID:          checkID + ".finding",
		CheckID:     checkID,
		Class:       class,
		Severity:    severity,
		Confidence:  model.ConfidenceConfirmed,
		Title:       "Demo finding",
		Why:         "Demo explanation",
		Remediation: "Demo remediation",
		Evidence: []model.Evidence{
			{Label: "demo", Detail: "evidence"},
		},
	}
}

func TestOrchestratorRendersMultipleOutputsConcurrently(t *testing.T) {
	t.Parallel()

	execution, err := runner.NewExecutionContext(model.AuditConfig{}, stubExecutor{})
	if err != nil {
		t.Fatalf("NewExecutionContext() error = %v", err)
	}

	var out1, out2 bytes.Buffer
	reportData, err := orchestrator.Orchestrator{
		Execution: execution,
		Discovery: discovery.NoopService{},
		Checks: []checks.Check{
			stubCheck{
				id: "checks.demo",
				result: model.CheckResult{
					Findings: []model.Finding{sampleFinding("checks.demo", model.FindingClassDirect, model.SeverityHigh)},
				},
			},
		},
		Outputs: []orchestrator.Output{
			{Reporter: stubReporter{format: "terminal"}, Writer: &out1},
			{Reporter: stubReporter{format: "json"}, Writer: &out2},
		},
	}.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if reportData.Summary.TotalFindings != 1 {
		t.Fatalf("expected 1 finding, got %d", reportData.Summary.TotalFindings)
	}
	if !strings.Contains(out1.String(), "findings=1") {
		t.Fatalf("expected first output to contain findings, got %q", out1.String())
	}
	if !strings.Contains(out2.String(), "findings=1") {
		t.Fatalf("expected second output to contain findings, got %q", out2.String())
	}
}

func TestOrchestratorMultiOutputRenderErrorReported(t *testing.T) {
	t.Parallel()

	execution, err := runner.NewExecutionContext(model.AuditConfig{}, stubExecutor{})
	if err != nil {
		t.Fatalf("NewExecutionContext() error = %v", err)
	}

	_, err = orchestrator.Orchestrator{
		Execution: execution,
		Discovery: discovery.NoopService{},
		Outputs: []orchestrator.Output{
			{Reporter: stubReporter{format: "terminal"}, Writer: &bytes.Buffer{}},
			{Reporter: stubReporter{format: "json", err: errors.New("render failed")}, Writer: &bytes.Buffer{}},
		},
	}.Run(context.Background())
	if err == nil {
		t.Fatal("expected report-stage error from multi-output render")
	}

	if got := runner.StageForError(err); got != progress.StageReport {
		t.Fatalf("StageForError() = %q", got)
	}
}

func findEvent(events []progress.Event, eventType progress.EventType, stage progress.Stage) progress.Event {
	for _, event := range events {
		if event.Type == eventType && event.Stage == stage {
			return event
		}
	}

	return progress.Event{}
}
