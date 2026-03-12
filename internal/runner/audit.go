package runner

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"time"

	"github.com/nagi/larainspect/internal/checks"
	"github.com/nagi/larainspect/internal/correlators"
	"github.com/nagi/larainspect/internal/discovery"
	"github.com/nagi/larainspect/internal/model"
)

type Auditor struct {
	Discovery   discovery.Service
	Checks      []checks.Check
	Correlators []correlators.Correlator
}

var (
	ErrMissingCommandExecutor  = errors.New("missing command executor")
	ErrMissingDiscoveryService = errors.New("missing discovery service")
)

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

	snapshot, unknowns, err := auditor.Discovery.Discover(ctx, execution)
	if err != nil {
		return model.Report{}, err
	}

	var findings []model.Finding
	collectedUnknowns := append([]model.Unknown{}, unknowns...)

	for _, check := range auditor.Checks {
		result, runErr := check.Run(ctx, execution, snapshot)
		if runErr != nil {
			collectedUnknowns = append(collectedUnknowns, model.Unknown{
				ID:      check.ID() + ".error",
				CheckID: check.ID(),
				Title:   "Check execution failed",
				Reason:  runErr.Error(),
				Error:   model.ErrorKindCommandFailed,
			})
			continue
		}

		findings = append(findings, result.Findings...)
		collectedUnknowns = append(collectedUnknowns, result.Unknowns...)
	}

	for _, correlator := range auditor.Correlators {
		result, correlateErr := correlator.Correlate(ctx, execution, snapshot, findings)
		if correlateErr != nil {
			collectedUnknowns = append(collectedUnknowns, model.Unknown{
				ID:      correlator.ID() + ".error",
				CheckID: correlator.ID(),
				Title:   "Correlation execution failed",
				Reason:  correlateErr.Error(),
				Error:   model.ErrorKindCommandFailed,
			})
			continue
		}

		findings = append(findings, result.Findings...)
		collectedUnknowns = append(collectedUnknowns, result.Unknowns...)
	}

	return model.BuildReport(execution.Host, time.Now().UTC(), time.Since(startedAt), findings, collectedUnknowns)
}

func runtimeHostname() (string, error) {
	return osHostname()
}
