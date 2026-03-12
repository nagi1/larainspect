package checks

import (
	"context"
	"fmt"
	"strings"

	"github.com/nagi1/larainspect/internal/model"
)

const appValidationCheckID = "app.validation"

type AppValidationCheck struct{}

func init() {
	MustRegister(AppValidationCheck{})
}

func (AppValidationCheck) ID() string {
	return appValidationCheckID
}

func (AppValidationCheck) Run(_ context.Context, _ model.ExecutionContext, snapshot model.Snapshot) (model.CheckResult, error) {
	findings := []model.Finding{}

	for _, app := range snapshot.Apps {
		if ambiguousRootFinding, found := buildAmbiguousRootFinding(app); found {
			findings = append(findings, ambiguousRootFinding)
		}

		if missingCorePathsFinding, found := buildMissingCorePathsFinding(app); found {
			findings = append(findings, missingCorePathsFinding)
		}
	}

	return model.CheckResult{Findings: findings}, nil
}

func buildAmbiguousRootFinding(app model.LaravelApp) (model.Finding, bool) {
	if strings.TrimSpace(app.ResolvedPath) == "" || app.ResolvedPath == app.RootPath {
		return model.Finding{}, false
	}

	return model.Finding{
		ID:          buildFindingID(appValidationCheckID, "ambiguous_root", app.RootPath),
		CheckID:     appValidationCheckID,
		Class:       model.FindingClassDirect,
		Severity:    model.SeverityLow,
		Confidence:  model.ConfidenceConfirmed,
		Title:       "Application root resolves through a different path",
		Why:         "Symlinked or indirect app roots make web, deploy, and runtime boundaries harder to reason about during an audit.",
		Remediation: "Document the canonical release path, audit the resolved target, and keep service and web roots pointed at one intentional location.",
		Evidence: []model.Evidence{
			{Label: "requested_root", Detail: app.RootPath},
			{Label: "resolved_root", Detail: app.ResolvedPath},
		},
		Affected: []model.Target{
			appTarget(app),
		},
	}, true
}

func buildMissingCorePathsFinding(app model.LaravelApp) (model.Finding, bool) {
	missingPaths := []string{}
	wrongKindPaths := []string{}
	evidence := []model.Evidence{}

	for _, expectation := range model.CoreLaravelPathExpectations() {
		if !expectation.Required {
			continue
		}

		pathRecord, found := app.PathRecord(expectation.RelativePath)
		if !found || !pathRecord.Inspected {
			continue
		}

		if !pathRecord.Exists {
			missingPaths = append(missingPaths, expectation.RelativePath)
			evidence = append(evidence, model.Evidence{
				Label:  "missing_path",
				Detail: filepathForEvidence(app.RootPath, expectation.RelativePath),
			})
			continue
		}

		if pathRecord.EffectiveKind() != expectation.Kind {
			wrongKindPaths = append(wrongKindPaths, fmt.Sprintf("%s (%s)", expectation.RelativePath, pathRecord.EffectiveKind()))
			evidence = append(evidence, model.Evidence{
				Label:  "unexpected_type",
				Detail: fmt.Sprintf("%s is %s", pathRecord.AbsolutePath, pathRecord.EffectiveKind()),
			})
		}
	}

	if len(missingPaths) == 0 && len(wrongKindPaths) == 0 {
		return model.Finding{}, false
	}

	why := "A partial or structurally inconsistent Laravel root makes later security findings harder to trust and often points to a broken release or the wrong scan target."
	if len(wrongKindPaths) == 0 {
		why = "Missing core Laravel paths usually mean the audit target is incomplete, broken, or not the intended deployed application root."
	}

	return model.Finding{
		ID:          buildFindingID(appValidationCheckID, "missing_core_paths", app.RootPath),
		CheckID:     appValidationCheckID,
		Class:       model.FindingClassDirect,
		Severity:    model.SeverityMedium,
		Confidence:  model.ConfidenceConfirmed,
		Title:       "Application is missing expected Laravel paths",
		Why:         why,
		Remediation: "Verify the selected app path points at a complete Laravel release and restore any missing core directories or files before trusting the audit result.",
		Evidence:    evidence,
		Affected: []model.Target{
			appTarget(app),
		},
	}, true
}

func filepathForEvidence(rootPath string, relativePath string) string {
	if strings.TrimSpace(rootPath) == "" {
		return relativePath
	}

	return rootPath + "/" + relativePath
}
