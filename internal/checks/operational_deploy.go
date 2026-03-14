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
				Title:       "Live app tree contains version-control metadata",
				Why:         "A deployed .git or similar VCS path leaks repository history and can expose operational drift or sensitive project state if it becomes readable.",
				Remediation: "Keep version-control metadata out of live application trees and deploy from release artifacts or clean export directories.",
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
				Title:       "Composer runs as root for a Laravel app workflow",
				Why:         "Root-run Composer or deploy hooks make ownership drift and privileged post-install script execution much more dangerous in production.",
				Remediation: "Run Composer and deploy hooks as the intended deploy identity, not root, and keep post-deploy ownership verification explicit.",
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
				Title:       "Deploy or maintenance command applies dangerous recursive ownership or mode changes",
				Why:         "Recursive chmod or chown commands against the Laravel tree create permission drift, can hand code ownership to the runtime user, and often undo a hardened deploy model.",
				Remediation: "Remove blanket recursive chmod or chown commands and enforce the intended deploy/runtime split with explicit narrow path ownership rules.",
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
				Title:       "Restore or artisan maintenance workflow runs as root",
				Why:         "Root-run restore or cache-maintenance steps commonly create ownership drift and can make Laravel config or cache artifacts unexpectedly privileged.",
				Remediation: "Run restore and artisan maintenance steps as the intended deploy identity and verify ownership after the workflow completes.",
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

		if finding, found := buildPostDeployDriftFinding(app, snapshot); found {
			findings = append(findings, finding)
		}
		if finding, found := buildPostRestoreDriftFinding(app, snapshot); found {
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
		Title:       "Deployment appears to mutate one live app tree in place",
		Why:         "In-place deploys make rollback, immutability, and permission-drift control harder than a release-based current-plus-releases model.",
		Remediation: "Prefer a release-based deployment layout with immutable releases, a current symlink switch, and shared writable paths kept outside release code.",
		Evidence: []model.Evidence{
			{Label: "app_root", Detail: app.RootPath},
			{Label: "deployment_model", Detail: "in_place_or_not_detected_as_release_based"},
		},
		Affected: []model.Target{appTarget(app)},
	}}
}
