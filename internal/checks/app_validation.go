package checks

import (
	"context"
	"fmt"
	"strings"

	"github.com/nagi1/larainspect/internal/model"
)

const appValidationCheckID = "app.validation"

var _ Check = AppValidationCheck{}

type AppValidationCheck struct{}

func init() {
	MustRegister(AppValidationCheck{})
}

func (AppValidationCheck) ID() string {
	return appValidationCheckID
}

func (AppValidationCheck) Description() string {
	return "Validate discovered Laravel applications and required project markers."
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
		Title:       "App path resolves to a different directory than expected",
		Why:         "The selected app path is a symlink or indirect path, which makes it easier to audit the wrong directory or misunderstand where the live code really is.",
		Remediation: "Document the real app path, audit that resolved directory, and make the web server, PHP-FPM, and deploy tooling all point to the same intended location.",
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

	why := "The selected app path does not look like a complete Laravel app. This often means the release is broken or the scan is pointing at the wrong directory."
	if len(wrongKindPaths) == 0 {
		why = "Required Laravel files or directories are missing, which usually means the app is incomplete, broken, or not the real deployed root."
	}

	return model.Finding{
		ID:          buildFindingID(appValidationCheckID, "missing_core_paths", app.RootPath),
		CheckID:     appValidationCheckID,
		Class:       model.FindingClassDirect,
		Severity:    model.SeverityMedium,
		Confidence:  model.ConfidenceConfirmed,
		Title:       "Selected app path is missing required Laravel files or directories",
		Why:         why,
		Remediation: "Verify the scan points at a complete Laravel release, then restore any missing required files or directories before relying on the audit result.",
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
