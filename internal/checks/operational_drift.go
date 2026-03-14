package checks

import (
	"path/filepath"
	"strings"

	"github.com/nagi1/larainspect/internal/model"
)

type appDriftCorrelation struct {
	evidence      []model.Evidence
	affected      []model.Target
	seenEvidence  map[string]struct{}
	seenTargets   map[string]struct{}
	seenSummaries map[string]struct{}
	signals       int
	critical      bool
}

func newAppDriftCorrelation(app model.LaravelApp) appDriftCorrelation {
	correlation := appDriftCorrelation{
		evidence:      []model.Evidence{{Label: "app", Detail: app.RootPath}},
		affected:      []model.Target{},
		seenEvidence:  map[string]struct{}{"app\x00" + app.RootPath: {}},
		seenTargets:   map[string]struct{}{},
		seenSummaries: map[string]struct{}{},
	}
	correlation.addTarget(appTarget(app))
	return correlation
}

func (correlation *appDriftCorrelation) addSignal(summary string, critical bool, records ...model.PathRecord) {
	correlation.addEvidence(model.Evidence{Label: "drift_signal", Detail: summary})
	if _, found := correlation.seenSummaries[summary]; !found {
		correlation.seenSummaries[summary] = struct{}{}
		correlation.signals++
	}
	if critical {
		correlation.critical = true
	}
	for _, record := range records {
		correlation.addEvidence(pathEvidence(record)...)
		correlation.addTarget(pathTarget(record))
	}
}

func (correlation *appDriftCorrelation) addEvidence(evidence ...model.Evidence) {
	for _, entry := range evidence {
		key := entry.Label + "\x00" + entry.Detail
		if _, found := correlation.seenEvidence[key]; found {
			continue
		}
		correlation.seenEvidence[key] = struct{}{}
		correlation.evidence = append(correlation.evidence, entry)
	}
}

func (correlation *appDriftCorrelation) addTarget(target model.Target) {
	key := target.Type + "\x00" + target.Path + "\x00" + target.Name + "\x00" + target.Value
	if _, found := correlation.seenTargets[key]; found {
		return
	}
	correlation.seenTargets[key] = struct{}{}
	correlation.affected = append(correlation.affected, target)
}

func (correlation appDriftCorrelation) severity() model.Severity {
	if correlation.critical {
		return model.SeverityCritical
	}
	return model.SeverityHigh
}

func (correlation appDriftCorrelation) qualifiesForCorrelation(workflowCount int) bool {
	if correlation.signals >= 2 {
		return true
	}

	return correlation.signals == 1 && correlation.critical && workflowCount > 0
}

func collectAppDriftCorrelation(app model.LaravelApp, snapshot model.Snapshot) appDriftCorrelation {
	correlation := newAppDriftCorrelation(app)
	runtimeIdentities := collectAppRuntimeIdentities(app, snapshot)

	if len(runtimeIdentities.Users) > 0 || len(runtimeIdentities.Groups) > 0 {
		correlation.addEvidence(runtimeIdentityEvidence(runtimeIdentities)...)
	}

	if envPath, found := app.PathRecord(".env"); found && envPath.Inspected && envPath.Exists {
		if envPath.IsSymlink() && !symlinkedEnvironmentPathLooksExpected(app, envPath) {
			correlation.addSignal(".env points outside the expected deployment boundary", false, envPath)
		}
		if containsString(runtimeIdentities.Users, strings.TrimSpace(envPath.OwnerName)) {
			correlation.addSignal("the runtime owns .env", true, envPath)
		}
	}

	if app.RootRecord.Inspected && app.RootRecord.Exists && containsString(runtimeIdentities.Users, strings.TrimSpace(app.RootRecord.OwnerName)) {
		correlation.addSignal("the runtime owns the deployed code tree", true, app.RootRecord)
	}

	sensitiveRuntimeWritable := []model.PathRecord{}
	for _, relativePath := range sensitiveRuntimeBoundaryPaths() {
		pathRecord, found := app.PathRecord(relativePath)
		if !found || !pathWritableByRuntimeIdentity(pathRecord, runtimeIdentities) {
			continue
		}
		sensitiveRuntimeWritable = append(sensitiveRuntimeWritable, pathRecord)
	}
	if len(sensitiveRuntimeWritable) > 0 {
		correlation.addSignal("runtime identities can write code or .env outside Laravel's intended writable paths", true, sensitiveRuntimeWritable...)
	}

	broaderThanBaseline := []model.PathRecord{}
	for _, pathRecord := range app.KeyPaths {
		expectedMode, ok := expectedMaxModeForPath(pathRecord)
		if !ok || !pathModeExceeds(pathRecord, expectedMode) {
			continue
		}
		broaderThanBaseline = append(broaderThanBaseline, pathRecord)
	}
	if len(broaderThanBaseline) > 0 {
		correlation.addSignal("path permissions are broader than the hardened deployment baseline", false, broaderThanBaseline...)
	}

	if len(runtimeIdentities.Users) > 0 || len(runtimeIdentities.Groups) > 0 {
		missingWritableBaseline := []model.PathRecord{}
		for _, relativePath := range writableRuntimePaths() {
			pathRecord, found := app.PathRecord(relativePath)
			if !found || !pathRecord.Inspected || !pathRecord.Exists {
				continue
			}
			expectedMode, hasExpectedMode := expectedMaxModeForPath(pathRecord)
			if hasExpectedMode && pathModeExceeds(pathRecord, expectedMode) {
				continue
			}
			if pathWritableByRuntimeIdentity(pathRecord, runtimeIdentities) {
				continue
			}
			missingWritableBaseline = append(missingWritableBaseline, pathRecord)
		}
		if len(missingWritableBaseline) > 0 {
			correlation.addSignal("Laravel writable paths no longer match the intended runtime-writable baseline", false, missingWritableBaseline...)
		}
	}

	if publicStoragePath, found := appPublicStoragePath(app); found && strings.TrimSpace(publicStoragePath.ResolvedPath) != "" && !publicStorageSymlinkLooksExpected(app, publicStoragePath) {
		correlation.addSignal("public/storage resolves outside the expected shared storage target", true, publicStoragePath)
	}

	if app.Deployment.UsesReleaseLayout && strings.TrimSpace(app.Deployment.ReleaseRoot) != "" && strings.TrimSpace(app.ResolvedPath) != "" &&
		!pathIsWithinAnyRoot(app.ResolvedPath, []string{app.Deployment.ReleaseRoot}) {
		correlation.addSignal("the current release resolves outside the detected releases/ boundary", true)
		correlation.addEvidence(
			model.Evidence{Label: "current_release", Detail: app.ResolvedPath},
			model.Evidence{Label: "release_root", Detail: app.Deployment.ReleaseRoot},
		)
	}

	writablePreviousReleases := []model.PathRecord{}
	for _, previousRelease := range app.Deployment.PreviousReleases {
		if !pathRecordContainsUnsafeWriteBit(previousRelease) {
			continue
		}
		writablePreviousReleases = append(writablePreviousReleases, previousRelease)
	}
	if len(writablePreviousReleases) > 0 {
		correlation.addSignal("previous releases remain writable after deploy", false, writablePreviousReleases...)
	}

	return correlation
}

func operationalRecordsForApp(app model.LaravelApp, snapshot model.Snapshot, predicate func(string) bool) []operationalCommandRecord {
	records := []operationalCommandRecord{}

	for _, record := range operationalCommandRecords(snapshot) {
		if !predicate(record.Command) {
			continue
		}
		for _, matchedApp := range appsForOperationalCommand(snapshot.Apps, record) {
			if matchedApp.RootPath != app.RootPath {
				continue
			}
			records = append(records, record)
			break
		}
	}

	return records
}

func appendWorkflowContext(correlation *appDriftCorrelation, records []operationalCommandRecord, label string) {
	if len(records) == 0 {
		return
	}

	for _, record := range records {
		correlation.addEvidence(model.Evidence{Label: label, Detail: record.SourceType})
		correlation.addEvidence(commandEvidence(record)...)
		correlation.addTarget(model.Target{Type: "path", Path: record.SourcePath})
	}
}

func collectRecoveryArtifactDrift(app model.LaravelApp, correlation *appDriftCorrelation) {
	for _, artifact := range app.Artifacts {
		if !artifact.WithinPublicPath {
			continue
		}
		if !artifactLooksLikeRecoveryArtifact(artifact) {
			continue
		}
		correlation.addSignal("backup or restore artifacts remain under the public tree", true, artifact.Path)
	}
}

func artifactLooksLikeRecoveryArtifact(artifact model.ArtifactRecord) bool {
	if artifact.Kind == model.ArtifactKindEnvironmentBackup {
		return true
	}
	if artifact.Kind != model.ArtifactKindPublicSensitiveFile {
		return false
	}

	relativePath := strings.ToLower(filepath.ToSlash(artifact.Path.RelativePath))
	return strings.Contains(relativePath, "backup") ||
		strings.Contains(relativePath, "dump") ||
		strings.HasSuffix(relativePath, ".sql") ||
		strings.HasSuffix(relativePath, ".sql.gz") ||
		strings.HasSuffix(relativePath, ".zip") ||
		strings.HasSuffix(relativePath, ".tar") ||
		strings.HasSuffix(relativePath, ".tar.gz") ||
		strings.HasSuffix(relativePath, ".tgz")
}

func buildPostDeployDriftFinding(app model.LaravelApp, snapshot model.Snapshot) (model.Finding, bool) {
	correlation := collectAppDriftCorrelation(app, snapshot)
	deployRecords := operationalRecordsForApp(app, snapshot, commandLooksLikeDeploymentWorkflow)
	if !correlation.qualifiesForCorrelation(len(deployRecords)) {
		return model.Finding{}, false
	}
	appendWorkflowContext(&correlation, deployRecords, "deploy_workflow")
	if len(deployRecords) == 0 {
		correlation.addEvidence(model.Evidence{Label: "deploy_workflow", Detail: "no explicit deploy command was matched; finding is based on deployed-path state"})
	}

	return model.Finding{
		ID:          buildFindingID(operationalDeployCheckID, "post_deploy_drift", app.RootPath),
		CheckID:     operationalDeployCheckID,
		Class:       model.FindingClassDirect,
		Severity:    correlation.severity(),
		Confidence:  model.ConfidenceConfirmed,
		Title:       "Deployment left Laravel ownership or writable paths in an unsafe state",
		Why:         "After deployment, the app no longer matches the expected safe layout. Code, .env, symlinks, or old releases may now be writable or owned by the wrong account, which makes later compromise or mistakes more damaging.",
		Remediation: "Add a post-deploy verification step that checks .env and code are not writable by the runtime, only storage/ and bootstrap/cache/ stay writable, symlinks point where you expect, and old releases are read-only.",
		Evidence:    correlation.evidence,
		Affected:    correlation.affected,
	}, true
}

func buildPostRestoreDriftFinding(app model.LaravelApp, snapshot model.Snapshot) (model.Finding, bool) {
	restoreRecords := operationalRecordsForApp(app, snapshot, commandLooksLikeRecoveryWorkflow)
	if len(restoreRecords) == 0 {
		return model.Finding{}, false
	}

	correlation := collectAppDriftCorrelation(app, snapshot)
	collectRecoveryArtifactDrift(app, &correlation)
	if !correlation.qualifiesForCorrelation(len(restoreRecords)) {
		return model.Finding{}, false
	}

	appendWorkflowContext(&correlation, restoreRecords, "restore_workflow")

	return model.Finding{
		ID:          buildFindingID(operationalDeployCheckID, "post_restore_drift", app.RootPath),
		CheckID:     operationalDeployCheckID,
		Class:       model.FindingClassDirect,
		Severity:    correlation.severity(),
		Confidence:  model.ConfidenceProbable,
		Title:       "Restore left Laravel ownership or shared paths in an unsafe state",
		Why:         "After a restore, the app no longer matches the expected safe layout. Code ownership, writable paths, symlinks, old releases, or recovery artifacts may now be in the wrong place or too permissive.",
		Remediation: "After each restore, verify code and .env ownership, writable paths, shared-path symlinks, release immutability, and backup artifact placement before putting the app back into service.",
		Evidence:    correlation.evidence,
		Affected:    correlation.affected,
	}, true
}
