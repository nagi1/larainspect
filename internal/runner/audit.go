package runner

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/nagi1/larainspect/internal/checks"
	"github.com/nagi1/larainspect/internal/correlators"
	"github.com/nagi1/larainspect/internal/discovery"
	"github.com/nagi1/larainspect/internal/model"
	"github.com/nagi1/larainspect/internal/progress"
)

type Auditor struct {
	Discovery   discovery.Service
	Checks      []checks.Check
	Correlators []correlators.Correlator
	ProgressBus *progress.Bus
}

var (
	ErrMissingCommandExecutor  = errors.New("missing command executor")
	ErrMissingDiscoveryService = errors.New("missing discovery service")
)

type AuditStageError struct {
	Stage progress.Stage
	Err   error
}

func (err AuditStageError) Error() string {
	if err.Err == nil {
		return ""
	}

	return err.Err.Error()
}

func (err AuditStageError) Unwrap() error {
	return err.Err
}

func StageForError(err error) progress.Stage {
	var stageErr AuditStageError
	if errors.As(err, &stageErr) {
		return stageErr.Stage
	}

	return progress.StageReport
}

func DefaultWorkerLimit() int {
	if runtime.NumCPU() < 4 {
		return runtime.NumCPU()
	}

	return 4
}

func NewExecutionContext(config model.AuditConfig, commands model.CommandExecutor) (model.ExecutionContext, error) {
	if commands == nil {
		return model.ExecutionContext{}, ErrMissingCommandExecutor
	}

	hostname, err := runtimeHostname()
	if err != nil {
		return model.ExecutionContext{}, err
	}

	if config.WorkerLimit <= 0 {
		config.WorkerLimit = DefaultWorkerLimit()
	}

	if config.CommandTimeout <= 0 {
		config.CommandTimeout = 2 * time.Second
	}

	if config.MaxOutputBytes <= 0 {
		config.MaxOutputBytes = 64 * 1024
	}

	return model.ExecutionContext{
		AuditID:   fmt.Sprintf("audit-%d", time.Now().UTC().UnixNano()),
		StartedAt: time.Now().UTC(),
		Config:    config,
		Host: model.Host{
			Hostname: hostname,
			OS:       runtime.GOOS,
			Arch:     runtime.GOARCH,
		},
		Tools:    model.ToolAvailability{},
		Commands: commands,
	}, nil
}

func (auditor Auditor) Run(ctx context.Context, execution model.ExecutionContext) (model.Report, error) {
	if auditor.Discovery == nil {
		return model.Report{}, ErrMissingDiscoveryService
	}

	startedAt := execution.StartedAt

	auditor.publish(progress.Event{
		Type:    progress.EventStageStarted,
		Stage:   progress.StageDiscovery,
		Message: "collecting host and Laravel evidence",
	})

	snapshot, unknowns, err := auditor.Discovery.Discover(ctx, execution)
	if err != nil {
		return model.Report{}, AuditStageError{Stage: progress.StageDiscovery, Err: err}
	}

	auditor.publish(discoveryContextEvent(snapshot))
	auditor.publish(progress.Event{
		Type:    progress.EventStageCompleted,
		Stage:   progress.StageDiscovery,
		Message: discoverySummary(snapshot, len(unknowns)),
	})

	var findings []model.Finding
	collectedUnknowns := append([]model.Unknown{}, unknowns...)

	auditor.publish(progress.Event{
		Type:    progress.EventStageStarted,
		Stage:   progress.StageChecks,
		Message: fmt.Sprintf("running %d registered checks", len(auditor.Checks)),
	})

	checkTotal := len(auditor.Checks)
	for _, check := range auditor.Checks {
		auditor.publish(progress.Event{
			Type:        progress.EventCheckRegistered,
			Stage:       progress.StageChecks,
			ComponentID: check.ID(),
			Message:     check.Description(),
			Total:       checkTotal,
		})
	}

	type checkOutput struct {
		checkID string
		result  model.CheckResult
		err     error
	}

	outputs := make([]checkOutput, checkTotal)
	var mu sync.Mutex
	var completed int

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(execution.Config.WorkerLimit)

	for i, check := range auditor.Checks {
		auditor.publish(progress.Event{
			Type:        progress.EventCheckStarted,
			Stage:       progress.StageChecks,
			ComponentID: check.ID(),
			Completed:   i,
			Total:       checkTotal,
		})

		g.Go(func() error {
			result, runErr := check.Run(gctx, execution, snapshot)

			mu.Lock()
			completed++
			done := completed
			mu.Unlock()

			outputs[i] = checkOutput{checkID: check.ID(), result: result, err: runErr}

			if runErr != nil {
				auditor.publish(progress.Event{
					Type:        progress.EventCheckFailed,
					Stage:       progress.StageChecks,
					ComponentID: check.ID(),
					Err:         runErr,
					Completed:   done,
					Total:       checkTotal,
				})
			} else {
				auditor.publishCheckResults(progress.StageChecks, check.ID(), result)
				auditor.publish(progress.Event{
					Type:        progress.EventCheckCompleted,
					Stage:       progress.StageChecks,
					ComponentID: check.ID(),
					Findings:    len(result.Findings),
					Unknowns:    len(result.Unknowns),
					Completed:   done,
					Total:       checkTotal,
				})
			}

			return nil // never fail the group; collect per-check errors
		})
	}

	_ = g.Wait()

	for _, out := range outputs {
		if out.err != nil {
			collectedUnknowns = append(collectedUnknowns, executionUnknown(out.checkID, "Check execution failed", out.err))
			continue
		}
		findings = append(findings, out.result.Findings...)
		collectedUnknowns = append(collectedUnknowns, out.result.Unknowns...)
	}

	auditor.publish(progress.Event{
		Type:    progress.EventStageCompleted,
		Stage:   progress.StageChecks,
		Message: findingsSummary(findings, collectedUnknowns),
	})

	auditor.publish(progress.Event{
		Type:    progress.EventStageStarted,
		Stage:   progress.StageCorrelation,
		Message: fmt.Sprintf("running %d correlators", len(auditor.Correlators)),
	})

	correlatorTotal := len(auditor.Correlators)
	for _, correlator := range auditor.Correlators {
		auditor.publish(progress.Event{
			Type:        progress.EventCorrelatorRegistered,
			Stage:       progress.StageCorrelation,
			ComponentID: correlator.ID(),
			Message:     correlator.Description(),
			Total:       correlatorTotal,
		})
	}

	type correlatorOutput struct {
		correlatorID string
		result       model.CheckResult
		err          error
	}

	correlatorOutputs := make([]correlatorOutput, correlatorTotal)
	var correlatorCompleted int

	cg, cgctx := errgroup.WithContext(ctx)
	cg.SetLimit(execution.Config.WorkerLimit)

	// Take a snapshot of current findings for correlators to read concurrently.
	// Correlators must not see each other's findings — they see only check-stage findings.
	correlatorFindings := make([]model.Finding, len(findings))
	copy(correlatorFindings, findings)

	for i, correlator := range auditor.Correlators {
		auditor.publish(progress.Event{
			Type:        progress.EventCorrelatorStarted,
			Stage:       progress.StageCorrelation,
			ComponentID: correlator.ID(),
			Completed:   i,
			Total:       correlatorTotal,
		})

		cg.Go(func() error {
			result, correlateErr := correlator.Correlate(cgctx, execution, snapshot, correlatorFindings)

			mu.Lock()
			correlatorCompleted++
			done := correlatorCompleted
			mu.Unlock()

			correlatorOutputs[i] = correlatorOutput{correlatorID: correlator.ID(), result: result, err: correlateErr}

			if correlateErr != nil {
				auditor.publish(progress.Event{
					Type:        progress.EventCorrelatorFailed,
					Stage:       progress.StageCorrelation,
					ComponentID: correlator.ID(),
					Err:         correlateErr,
					Completed:   done,
					Total:       correlatorTotal,
				})
			} else {
				auditor.publishCheckResults(progress.StageCorrelation, correlator.ID(), result)
				auditor.publish(progress.Event{
					Type:        progress.EventCorrelatorCompleted,
					Stage:       progress.StageCorrelation,
					ComponentID: correlator.ID(),
					Findings:    len(result.Findings),
					Unknowns:    len(result.Unknowns),
					Completed:   done,
					Total:       correlatorTotal,
				})
			}

			return nil
		})
	}

	_ = cg.Wait()

	for _, out := range correlatorOutputs {
		if out.err != nil {
			collectedUnknowns = append(collectedUnknowns, executionUnknown(out.correlatorID, "Correlation execution failed", out.err))
			continue
		}
		findings = append(findings, out.result.Findings...)
		collectedUnknowns = append(collectedUnknowns, out.result.Unknowns...)
	}

	auditor.publish(progress.Event{
		Type:    progress.EventStageCompleted,
		Stage:   progress.StageCorrelation,
		Message: findingsSummary(findings, collectedUnknowns),
	})

	report, buildErr := model.BuildReport(execution.Host, time.Now().UTC(), time.Since(startedAt), findings, collectedUnknowns)
	if buildErr != nil {
		return model.Report{}, AuditStageError{Stage: progress.StageReport, Err: buildErr}
	}

	return report, nil
}

func runtimeHostname() (string, error) {
	return osHostname()
}

func executionUnknown(checkID string, title string, err error) model.Unknown {
	return model.Unknown{
		ID:      checkID + ".error",
		CheckID: checkID,
		Title:   title,
		Reason:  err.Error(),
		Error:   model.ErrorKindCommandFailed,
	}
}

func (auditor Auditor) publish(event progress.Event) {
	if auditor.ProgressBus == nil {
		return
	}

	if event.At.IsZero() {
		event.At = time.Now().UTC()
	}

	auditor.ProgressBus.Publish(event)
}

func (auditor Auditor) publishCheckResults(stage progress.Stage, componentID string, result model.CheckResult) {
	for _, finding := range result.Findings {
		auditor.publish(progress.Event{
			Type:        progress.EventFindingDiscovered,
			Stage:       stage,
			ComponentID: componentID,
			Severity:    finding.Severity,
			Class:       finding.Class,
			Title:       finding.Title,
		})
	}

	for _, unknown := range result.Unknowns {
		auditor.publish(progress.Event{
			Type:        progress.EventUnknownObserved,
			Stage:       stage,
			ComponentID: componentID,
			ErrorKind:   unknown.Error,
			Title:       unknown.Title,
		})
	}
}

func discoverySummary(snapshot model.Snapshot, unknownCount int) string {
	return fmt.Sprintf(
		"apps=%d nginx_sites=%d php_fpm_pools=%d listeners=%d unknowns=%d",
		len(snapshot.Apps),
		len(snapshot.NginxSites),
		len(snapshot.PHPFPMPools),
		len(snapshot.Listeners),
		unknownCount,
	)
}

func discoveryContextEvent(snapshot model.Snapshot) progress.Event {
	event := progress.Event{
		Type:        progress.EventContextResolved,
		Stage:       progress.StageDiscovery,
		AppCount:    len(snapshot.Apps),
		NginxSites:  len(snapshot.NginxSites),
		PHPFPMPools: len(snapshot.PHPFPMPools),
		Listeners:   len(snapshot.Listeners),
	}

	if len(snapshot.Apps) == 0 {
		return event
	}

	primaryApp := snapshot.Apps[0]
	event.AppName = primaryApp.DisplayName()
	event.AppPath = primaryApp.RootPath
	event.LaravelVersion = primaryApp.EffectiveLaravelVersion()
	event.PHPVersion = primaryApp.PHPVersion
	event.PackageCount = len(primaryApp.Packages)
	event.ArtifactCount = len(primaryApp.Artifacts)
	event.SourceMatches = len(primaryApp.SourceMatches)

	return event
}

func findingsSummary(findings []model.Finding, unknowns []model.Unknown) string {
	direct := 0
	heuristic := 0
	compromise := 0

	for _, finding := range findings {
		switch finding.Class {
		case model.FindingClassDirect:
			direct++
		case model.FindingClassHeuristic:
			heuristic++
		case model.FindingClassCompromiseIndicator:
			compromise++
		}
	}

	return fmt.Sprintf(
		"direct=%d heuristic=%d compromise=%d unknowns=%d",
		direct,
		heuristic,
		compromise,
		len(unknowns),
	)
}
