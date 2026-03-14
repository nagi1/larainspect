package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/nagi1/larainspect/internal/baseline"
	"github.com/nagi1/larainspect/internal/checks"
	"github.com/nagi1/larainspect/internal/correlators"
	"github.com/nagi1/larainspect/internal/discovery"
	"github.com/nagi1/larainspect/internal/model"
	"github.com/nagi1/larainspect/internal/progress"
	"github.com/nagi1/larainspect/internal/report"
	"github.com/nagi1/larainspect/internal/runner"
	"github.com/nagi1/larainspect/internal/store"
)

var (
	ErrMissingOutputs      = errors.New("missing report outputs")
	ErrMissingReporter     = errors.New("missing reporter")
	ErrMissingOutputWriter = errors.New("missing output writer")
)

type Output struct {
	Reporter report.Reporter
	Writer   io.Writer
}

// Orchestrator coordinates the full Larainspect audit lifecycle.
type Orchestrator struct {
	Execution   model.ExecutionContext
	Discovery   discovery.Service
	Checks      []checks.Check
	Correlators []correlators.Correlator
	Outputs     []Output
	ProgressBus *progress.Bus
}

func (orchestrator Orchestrator) Run(ctx context.Context) (model.Report, error) {
	if orchestrator.Discovery == nil {
		return model.Report{}, runner.AuditStageError{Stage: progress.StageDiscovery, Err: runner.ErrMissingDiscoveryService}
	}

	if err := orchestrator.validateOutputs(); err != nil {
		return model.Report{}, runner.AuditStageError{Stage: progress.StageReport, Err: err}
	}

	orchestrator.publish(progress.Event{
		Type:    progress.EventAuditStarted,
		Stage:   progress.StageSetup,
		Message: "audit execution started",
	})
	orchestrator.publish(progress.Event{
		Type:    progress.EventStageStarted,
		Stage:   progress.StageSetup,
		Message: "preparing audit execution",
	})
	orchestrator.publish(progress.Event{
		Type:    progress.EventStageCompleted,
		Stage:   progress.StageSetup,
		Message: "configuration and command runner ready",
	})

	reportData, err := runner.Auditor{
		Discovery:   orchestrator.Discovery,
		Checks:      orchestrator.Checks,
		Correlators: orchestrator.Correlators,
		ProgressBus: orchestrator.ProgressBus,
	}.Run(ctx, orchestrator.Execution)
	if err != nil {
		orchestrator.publish(progress.Event{
			Type:  progress.EventAuditFailed,
			Stage: runner.StageForError(err),
			Err:   err,
		})
		return model.Report{}, err
	}

	orchestrator.publish(progress.Event{
		Type:    progress.EventStageStarted,
		Stage:   progress.StagePostProcess,
		Message: "applying post-processing rules",
	})

	postProcessedReport, postProcessMessage, err := orchestrator.postProcessReport(reportData)
	if err != nil {
		stageErr := runner.AuditStageError{Stage: progress.StagePostProcess, Err: err}
		orchestrator.publish(progress.Event{
			Type:  progress.EventAuditFailed,
			Stage: progress.StagePostProcess,
			Err:   stageErr,
		})
		return model.Report{}, stageErr
	}
	reportData = postProcessedReport

	orchestrator.publish(progress.Event{
		Type:     progress.EventStageCompleted,
		Stage:    progress.StagePostProcess,
		Message:  postProcessMessage,
		Findings: reportData.Summary.TotalFindings,
		Unknowns: reportData.Summary.Unknowns,
	})

	orchestrator.publish(progress.Event{
		Type:    progress.EventStageStarted,
		Stage:   progress.StageReport,
		Message: fmt.Sprintf("rendering %s output", orchestrator.outputFormats()),
	})

	var renderErr error
	if len(orchestrator.Outputs) == 1 {
		renderErr = orchestrator.Outputs[0].Reporter.Render(orchestrator.Outputs[0].Writer, reportData)
	} else {
		var wg sync.WaitGroup
		var mu sync.Mutex
		for _, output := range orchestrator.Outputs {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := output.Reporter.Render(output.Writer, reportData); err != nil {
					mu.Lock()
					if renderErr == nil {
						renderErr = err
					}
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
	}

	if renderErr != nil {
		stageErr := runner.AuditStageError{Stage: progress.StageReport, Err: renderErr}
		orchestrator.publish(progress.Event{
			Type:  progress.EventAuditFailed,
			Stage: progress.StageReport,
			Err:   stageErr,
		})
		return model.Report{}, stageErr
	}

	orchestrator.publish(progress.Event{
		Type:     progress.EventStageCompleted,
		Stage:    progress.StageReport,
		Message:  fmt.Sprintf("rendered report with %d findings and %d unknowns", reportData.Summary.TotalFindings, reportData.Summary.Unknowns),
		Findings: reportData.Summary.TotalFindings,
		Unknowns: reportData.Summary.Unknowns,
	})
	orchestrator.publish(progress.Event{
		Type:     progress.EventAuditCompleted,
		Stage:    progress.StageReport,
		Message:  fmt.Sprintf("audit complete: %d findings, %d unknowns", reportData.Summary.TotalFindings, reportData.Summary.Unknowns),
		Findings: reportData.Summary.TotalFindings,
		Unknowns: reportData.Summary.Unknowns,
		At:       time.Now().UTC(),
	})

	return reportData, nil
}

func (orchestrator Orchestrator) publish(event progress.Event) {
	if orchestrator.ProgressBus == nil {
		return
	}
	if event.At.IsZero() {
		event.At = time.Now().UTC()
	}
	orchestrator.ProgressBus.Publish(event)
}

func (orchestrator Orchestrator) outputFormats() string {
	formats := make([]string, 0, len(orchestrator.Outputs))
	for _, output := range orchestrator.Outputs {
		formats = append(formats, output.Reporter.Format())
	}

	return strings.Join(formats, ", ")
}

func (orchestrator Orchestrator) validateOutputs() error {
	if len(orchestrator.Outputs) == 0 {
		return ErrMissingOutputs
	}

	for _, output := range orchestrator.Outputs {
		if output.Reporter == nil {
			return ErrMissingReporter
		}
		if output.Writer == nil {
			return ErrMissingOutputWriter
		}
	}

	return nil
}

func (orchestrator Orchestrator) postProcessReport(reportData model.Report) (model.Report, string, error) {
	messageParts := []string{}

	if baselinePath := orchestrator.Execution.Config.NormalizedBaselinePath(); baselinePath != "" {
		reportBaseline, err := baseline.Load(baselinePath)
		if err != nil {
			return model.Report{}, "", err
		}

		activeFindings, suppressedCount := reportBaseline.Filter(reportData.Findings())
		messageParts = append(messageParts, fmt.Sprintf("baseline_suppressed=%d", suppressedCount))

		if suppressedCount > 0 {
			rebuiltReport, err := model.RebuildReport(reportData, activeFindings, reportData.Unknowns)
			if err != nil {
				return model.Report{}, "", err
			}
			reportData = rebuiltReport
		}
	}

	if len(messageParts) == 0 {
		messageParts = append(messageParts, "no configured post-processing filters")
	}

	if storeDir := orchestrator.Execution.Config.NormalizedStoreDir(); storeDir != "" {
		historyStore := store.New(storeDir)
		diff, err := historyStore.CompareLast(reportData)
		if err != nil {
			messageParts = append(messageParts, "history_compare=unavailable")
		} else if diff != nil {
			messageParts = append(messageParts, fmt.Sprintf("history_new=%d", len(diff.NewFindings)))
			messageParts = append(messageParts, fmt.Sprintf("history_resolved=%d", len(diff.ResolvedFindings)))
		} else {
			messageParts = append(messageParts, "history_compare=none")
		}
	}

	messageParts = append(messageParts, fmt.Sprintf("findings=%d", reportData.Summary.TotalFindings))
	messageParts = append(messageParts, fmt.Sprintf("unknowns=%d", reportData.Summary.Unknowns))

	return reportData, strings.Join(messageParts, " "), nil
}
