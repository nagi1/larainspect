package runner_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/nagi1/larainspect/internal/checks"
	"github.com/nagi1/larainspect/internal/correlators"
	"github.com/nagi1/larainspect/internal/discovery"
	"github.com/nagi1/larainspect/internal/model"
	"github.com/nagi1/larainspect/internal/progress"
	"github.com/nagi1/larainspect/internal/runner"
)

func TestNewExecutionContextRequiresCommandExecutor(t *testing.T) {
	t.Parallel()

	_, err := runner.NewExecutionContext(model.AuditConfig{}, nil)
	if !errors.Is(err, runner.ErrMissingCommandExecutor) {
		t.Fatalf("expected ErrMissingCommandExecutor, got %v", err)
	}
}

func TestAuditorConvertsCheckErrorsIntoUnknowns(t *testing.T) {
	t.Parallel()

	execution, err := runner.NewExecutionContext(model.AuditConfig{}, stubExecutor{})
	if err != nil {
		t.Fatalf("NewExecutionContext() error = %v", err)
	}

	report, err := runner.Auditor{
		Discovery: discovery.NoopService{},
		Checks: []checks.Check{
			stubCheck{
				id:  "demo.check",
				err: errors.New("boom"),
			},
		},
	}.Run(context.Background(), execution)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if len(report.Unknowns) != 1 {
		t.Fatalf("expected 1 unknown, got %d", len(report.Unknowns))
	}

	if report.Unknowns[0].CheckID != "demo.check" {
		t.Fatalf("expected unknown check id demo.check, got %q", report.Unknowns[0].CheckID)
	}
}

func TestAuditorCollectsCheckAndCorrelatorResults(t *testing.T) {
	t.Parallel()

	execution, err := runner.NewExecutionContext(model.AuditConfig{}, stubExecutor{})
	if err != nil {
		t.Fatalf("NewExecutionContext() error = %v", err)
	}

	report, err := runner.Auditor{
		Discovery: discovery.NoopService{},
		Checks: []checks.Check{
			stubCheck{
				id: "filesystem.demo",
				result: model.CheckResult{
					Findings: []model.Finding{sampleFinding("filesystem.demo", model.FindingClassDirect, model.SeverityHigh)},
				},
			},
		},
		Correlators: []correlators.Correlator{
			stubCorrelator{
				id: "correlation.demo",
				result: model.CheckResult{
					Findings: []model.Finding{sampleFinding("correlation.demo", model.FindingClassCompromiseIndicator, model.SeverityCritical)},
				},
			},
		},
	}.Run(context.Background(), execution)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if report.Summary.TotalFindings != 2 {
		t.Fatalf("expected 2 findings, got %d", report.Summary.TotalFindings)
	}

	if report.Summary.CompromiseIndicators != 1 {
		t.Fatalf("expected 1 compromise indicator, got %d", report.Summary.CompromiseIndicators)
	}

	if got := model.ExitCodeForReport(report); got != model.ExitCodeCriticalRisk {
		t.Fatalf("expected critical exit code, got %d", got)
	}
}

func TestAuditorRequiresDiscoveryService(t *testing.T) {
	t.Parallel()

	execution, err := runner.NewExecutionContext(model.AuditConfig{}, stubExecutor{})
	if err != nil {
		t.Fatalf("NewExecutionContext() error = %v", err)
	}

	_, err = runner.Auditor{}.Run(context.Background(), execution)
	if !errors.Is(err, runner.ErrMissingDiscoveryService) {
		t.Fatalf("expected ErrMissingDiscoveryService, got %v", err)
	}
}

func TestAuditorPublishesProgressEvents(t *testing.T) {
	t.Parallel()

	execution, err := runner.NewExecutionContext(model.AuditConfig{}, stubExecutor{})
	if err != nil {
		t.Fatalf("NewExecutionContext() error = %v", err)
	}

	bus := progress.NewBus()
	events := []progress.Event{}
	bus.SubscribeAll(func(event progress.Event) {
		events = append(events, event)
	})

	_, err = runner.Auditor{
		Discovery: discovery.NoopService{},
		Checks: []checks.Check{stubCheck{id: "checks.demo", result: model.CheckResult{
			Findings: []model.Finding{sampleFinding("checks.demo", model.FindingClassDirect, model.SeverityHigh)},
			Unknowns: []model.Unknown{{
				ID:      "checks.demo.unknown",
				CheckID: "checks.demo",
				Title:   "Demo unknown",
				Reason:  "permission denied",
				Error:   model.ErrorKindPermissionDenied,
			}},
		}}},
		Correlators: []correlators.Correlator{stubCorrelator{id: "correlation.demo"}},
		ProgressBus: bus,
	}.Run(context.Background(), execution)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	eventTypes := []progress.EventType{}
	for _, event := range events {
		eventTypes = append(eventTypes, event.Type)
	}

	for _, want := range []progress.EventType{
		progress.EventStageStarted,
		progress.EventStageCompleted,
		progress.EventContextResolved,
		progress.EventCheckRegistered,
		progress.EventCheckStarted,
		progress.EventFindingDiscovered,
		progress.EventUnknownObserved,
		progress.EventCheckCompleted,
		progress.EventCorrelatorRegistered,
		progress.EventCorrelatorStarted,
		progress.EventCorrelatorCompleted,
	} {
		if !slices.Contains(eventTypes, want) {
			t.Fatalf("expected progress event %q in %+v", want, eventTypes)
		}
	}

	checkStarted := findEvent(events, progress.EventCheckStarted)
	checkCompleted := findEvent(events, progress.EventCheckCompleted)
	checkRegistered := findEvent(events, progress.EventCheckRegistered)
	correlatorRegistered := findEvent(events, progress.EventCorrelatorRegistered)
	correlatorCompleted := findEvent(events, progress.EventCorrelatorCompleted)
	contextResolved := findEvent(events, progress.EventContextResolved)

	if checkRegistered.Total != 1 || checkRegistered.ComponentID != "checks.demo" {
		t.Fatalf("unexpected check registration %+v", checkRegistered)
	}
	if checkRegistered.Message != "stub check" {
		t.Fatalf("unexpected check registration description %+v", checkRegistered)
	}
	if checkStarted.Total != 1 || checkStarted.Completed != 0 {
		t.Fatalf("unexpected check start progress %+v", checkStarted)
	}
	if checkCompleted.Total != 1 || checkCompleted.Completed != 1 {
		t.Fatalf("unexpected check completion progress %+v", checkCompleted)
	}
	if correlatorRegistered.Total != 1 || correlatorRegistered.ComponentID != "correlation.demo" {
		t.Fatalf("unexpected correlator registration %+v", correlatorRegistered)
	}
	if correlatorRegistered.Message != "stub correlator" {
		t.Fatalf("unexpected correlator registration description %+v", correlatorRegistered)
	}
	if correlatorCompleted.Total != 1 || correlatorCompleted.Completed != 1 {
		t.Fatalf("unexpected correlator completion progress %+v", correlatorCompleted)
	}
	if contextResolved.AppCount != 0 || contextResolved.NginxSites != 0 || contextResolved.PHPFPMPools != 0 || contextResolved.Listeners != 0 {
		t.Fatalf("unexpected context resolved event %+v", contextResolved)
	}

	findingDiscovered := findEvent(events, progress.EventFindingDiscovered)
	unknownObserved := findEvent(events, progress.EventUnknownObserved)
	if findingDiscovered.Severity != model.SeverityHigh || findingDiscovered.Class != model.FindingClassDirect || findingDiscovered.Title != "Demo finding" {
		t.Fatalf("unexpected finding discovered event %+v", findingDiscovered)
	}
	if unknownObserved.ErrorKind != model.ErrorKindPermissionDenied || unknownObserved.Title != "Demo unknown" {
		t.Fatalf("unexpected unknown observed event %+v", unknownObserved)
	}
}

func TestStageForError(t *testing.T) {
	t.Parallel()

	if got := runner.StageForError(runner.AuditStageError{Stage: progress.StageDiscovery, Err: errors.New("boom")}); got != progress.StageDiscovery {
		t.Fatalf("StageForError() = %q", got)
	}

	if got := runner.StageForError(errors.New("plain")); got != progress.StageReport {
		t.Fatalf("StageForError() default = %q", got)
	}
}

func TestAuditStageErrorErrorAndUnwrap(t *testing.T) {
	t.Parallel()

	var empty runner.AuditStageError
	if empty.Error() != "" {
		t.Fatalf("expected empty error string, got %q", empty.Error())
	}

	inner := errors.New("boom")
	stageErr := runner.AuditStageError{Stage: progress.StageChecks, Err: inner}
	if stageErr.Error() != "boom" {
		t.Fatalf("Error() = %q", stageErr.Error())
	}
	if !errors.Is(stageErr.Unwrap(), inner) {
		t.Fatalf("expected unwrap to return inner error, got %v", stageErr.Unwrap())
	}
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

func findEvent(events []progress.Event, eventType progress.EventType) progress.Event {
	for _, event := range events {
		if event.Type == eventType {
			return event
		}
	}

	return progress.Event{}
}
