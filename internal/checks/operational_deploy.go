package checks

import (
	"context"
	"strings"

	"github.com/nagi1/larainspect/internal/model"
)

const operationalDeployCheckID = "operations.deploy"

var _ Check = OperationalDeployCheck{}

type OperationalDeployCheck struct{}

func init() {
	MustRegister(OperationalDeployCheck{})
}

func (OperationalDeployCheck) ID() string {
	return operationalDeployCheckID
}

func (OperationalDeployCheck) Description() string {
	return "Inspect deployment artifacts and release hygiene risks."
}

func (OperationalDeployCheck) Run(_ context.Context, execution model.ExecutionContext, snapshot model.Snapshot) (model.CheckResult, error) {
	findings := []model.Finding{}
	hostScope := execution.Config.Scope == model.ScanScopeHost

	for _, app := range snapshot.Apps {
		if hostScope {
			findings = append(findings, collectReleaseLayoutFindings(app)...)
		}

		for _, artifact := range app.Artifacts {
			if artifact.Kind != model.ArtifactKindVersionControlPath {
				continue
			}

			findings = append(findings, model.Finding{
				ID:          buildFindingID(operationalDeployCheckID, "version_control_path", artifact.Path.AbsolutePath),
				CheckID:     operationalDeployCheckID,
				Class:       model.FindingClassDirect,
				Severity:    model.SeverityHigh,
				Confidence:  model.ConfidenceConfirmed,
				Title:       "Live app directory still contains version-control files",
				Why:         "Leaving .git or similar metadata in the deployed app can expose repository history and internal project details if it becomes readable.",
				Remediation: "Deploy from a clean build artifact or export, and keep Git metadata out of the live app directory.",
				Evidence:    pathEvidence(artifact.Path),
				Affected: []model.Target{
					appTarget(app),
					pathTarget(artifact.Path),
				},
			})
		}
	}

	for _, record := range operationalCommandRecords(snapshot) {
		matchedApps := appsForOperationalCommand(snapshot.Apps, record)
		if len(matchedApps) == 0 {
			continue
		}

		if commandLooksLikeComposer(record.Command) && strings.EqualFold(record.RuntimeUser, "root") {
			findings = append(findings, model.Finding{
				ID:          buildFindingID(operationalDeployCheckID, "root_composer", record.SourcePath+"."+record.Name),
				CheckID:     operationalDeployCheckID,
				Class:       model.FindingClassDirect,
				Severity:    model.SeverityHigh,
				Confidence:  model.ConfidenceConfirmed,
				Title:       "Composer runs as root during deploy",
				Why:         "When Composer or its scripts run as root, they can create root-owned files and make permission mistakes much harder to recover from safely.",
				Remediation: "Run Composer and deploy hooks as the deploy user, not root, and verify file ownership after each deploy.",
				Evidence:    commandEvidence(record),
				Affected:    compactAppTargets(matchedApps),
			})
		}

		if commandLooksLikeComposerInstallWithoutNoDev(record.Command) {
			findings = append(findings, model.Finding{
				ID:          buildFindingID(operationalDeployCheckID, "composer_install_with_dev", record.SourcePath+"."+record.Name),
				CheckID:     operationalDeployCheckID,
				Class:       model.FindingClassHeuristic,
				Severity:    model.SeverityMedium,
				Confidence:  model.ConfidenceProbable,
				Title:       "Production workflow appears to run composer install without --no-dev",
				Why:         "Installing development dependencies on production systems increases attack surface and can expose debugging or testing tooling unintentionally.",
				Remediation: "Use composer install --no-dev for production deploy workflows and keep development-only packages out of the live runtime.",
				Evidence:    commandEvidence(record),
				Affected:    compactAppTargets(matchedApps),
			})
		}

		if commandLooksLikeDangerousPermissionReset(record.Command) {
			findings = append(findings, model.Finding{
				ID:          buildFindingID(operationalDeployCheckID, "dangerous_permission_reset", record.SourcePath+"."+record.Name),
				CheckID:     operationalDeployCheckID,
				Class:       model.FindingClassDirect,
				Severity:    model.SeverityCritical,
				Confidence:  model.ConfidenceConfirmed,
				Title:       "Deploy script resets ownership or permissions across the whole app",
				Why:         "Blanket recursive chmod or chown commands can accidentally hand code or secrets to the wrong user, undo a hardened deploy layout, and leave the next release in a weaker state.",
				Remediation: "Remove blanket recursive permission resets. Apply ownership and write access only to the exact paths that should change, usually storage/ and bootstrap/cache/.",
				Evidence:    commandEvidence(record),
				Affected:    compactAppTargets(matchedApps),
			})
		}

		if (commandLooksLikeRestoreWorkflow(record.Command) || commandLooksLikeArtisanMaintenance(record.Command)) && strings.EqualFold(record.RuntimeUser, "root") {
			findings = append(findings, model.Finding{
				ID:          buildFindingID(operationalDeployCheckID, "root_restore_or_maintenance", record.SourcePath+"."+record.Name),
				CheckID:     operationalDeployCheckID,
				Class:       model.FindingClassDirect,
				Severity:    model.SeverityHigh,
				Confidence:  model.ConfidenceConfirmed,
				Title:       "Restore or maintenance commands run as root",
				Why:         "Running restore, cache, or maintenance steps as root often leaves behind root-owned files and unexpected permission drift in the app directory.",
				Remediation: "Run restore and artisan maintenance steps as the deploy user, then verify ownership and permissions before the app serves traffic again.",
				Evidence:    commandEvidence(record),
				Affected:    compactAppTargets(matchedApps),
			})
		}
	}

	for _, app := range snapshot.Apps {
		for _, previousRelease := range app.Deployment.PreviousReleases {
			if !pathRecordContainsUnsafeWriteBit(previousRelease) {
				continue
			}

			findings = append(findings, model.Finding{
				ID:          buildFindingID(operationalDeployCheckID, "writable_previous_release", previousRelease.AbsolutePath),
				CheckID:     operationalDeployCheckID,
				Class:       model.FindingClassHeuristic,
				Severity:    model.SeverityMedium,
				Confidence:  model.ConfidenceProbable,
				Title:       "Previous release directory remains broadly writable",
				Why:         "Old release directories that retain group or world write access are easier to repurpose for persistence or drift than immutable historical releases.",
				Remediation: "Keep previous releases immutable after deployment and remove broad write access from old release trees.",
				Evidence:    pathEvidence(previousRelease),
				Affected: []model.Target{
					appTarget(app),
					pathTarget(previousRelease),
				},
			})
		}

		if finding, found := buildPostDeployDriftFinding(app, snapshot, execution.Config); found {
			findings = append(findings, finding)
		}
		if finding, found := buildPostRestoreDriftFinding(app, snapshot, execution.Config); found {
			findings = append(findings, finding)
		}
	}

	return model.CheckResult{Findings: findings}, nil
}

func collectReleaseLayoutFindings(app model.LaravelApp) []model.Finding {
	if app.Deployment.UsesReleaseLayout {
		return nil
	}

	return []model.Finding{{
		ID:          buildFindingID(operationalDeployCheckID, "mutable_live_tree", app.RootPath),
		CheckID:     operationalDeployCheckID,
		Class:       model.FindingClassHeuristic,
		Severity:    model.SeverityMedium,
		Confidence:  model.ConfidenceProbable,
		Title:       "Deployment updates the live app in place",
		Why:         "Updating the live app directory directly makes rollback harder and increases the chance of partial deploys or permission drift.",
		Remediation: "Prefer a release-based layout with separate release directories, a current symlink switch, and shared writable paths kept outside the release code.",
		Evidence: []model.Evidence{
			{Label: "app_root", Detail: app.RootPath},
			{Label: "deployment_model", Detail: "in_place_or_not_detected_as_release_based"},
		},
		Affected: []model.Target{appTarget(app)},
	}}
}
