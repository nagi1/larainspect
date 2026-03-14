package checks

import (
	"context"

	"github.com/nagi1/larainspect/internal/model"
)

const frameworkHeuristicsCheckID = "framework.heuristics"

var _ Check = FrameworkHeuristicsCheck{}

type FrameworkHeuristicsCheck struct{}

func init() {
	MustRegister(FrameworkHeuristicsCheck{})
}

func (FrameworkHeuristicsCheck) ID() string {
	return frameworkHeuristicsCheckID
}

func (FrameworkHeuristicsCheck) Description() string {
	return "Inspect Laravel source heuristics across framework and package conventions."
}

func (FrameworkHeuristicsCheck) Run(_ context.Context, _ model.ExecutionContext, snapshot model.Snapshot) (model.CheckResult, error) {
	findings := make([]model.Finding, 0)

	for _, app := range snapshot.Apps {
		findings = append(findings, buildLaravelFrameworkHeuristicFindings(app)...)
		findings = append(findings, buildLivewireFrameworkHeuristicFindings(app)...)
		findings = append(findings, buildFilamentFrameworkHeuristicFindings(app)...)
		findings = append(findings, buildFortifyFrameworkHeuristicFindings(app)...)
		findings = append(findings, buildInertiaFrameworkHeuristicFindings(app)...)
		findings = append(findings, buildAdminSurfaceHeuristicFindings(app)...)
	}

	return model.CheckResult{Findings: findings}, nil
}
