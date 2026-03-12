package runner_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nagi/larainspect/internal/checks"
	"github.com/nagi/larainspect/internal/correlators"
	"github.com/nagi/larainspect/internal/discovery"
	"github.com/nagi/larainspect/internal/model"
	"github.com/nagi/larainspect/internal/runner"
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
