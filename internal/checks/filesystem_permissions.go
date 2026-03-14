package checks

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/nagi1/larainspect/internal/model"
)

const filesystemPermissionsCheckID = "filesystem.permissions"

var _ Check = FilesystemPermissionsCheck{}

type FilesystemPermissionsCheck struct{}

func init() {
	MustRegister(FilesystemPermissionsCheck{})
}

func (FilesystemPermissionsCheck) ID() string {
	return filesystemPermissionsCheckID
}

func (FilesystemPermissionsCheck) Description() string {
	return "Inspect Laravel path ownership and writable permission boundaries."
}

func (FilesystemPermissionsCheck) Run(_ context.Context, _ model.ExecutionContext, snapshot model.Snapshot) (model.CheckResult, error) {
	findings := []model.Finding{}

	for _, app := range snapshot.Apps {
		runtimeIdentities := collectAppRuntimeIdentities(app, snapshot)
		finding, found := buildWorldWritablePathsFinding(app)
		findings = appendFindingIfPresent(findings, finding, found)
		finding, found = buildWorldReadableEnvironmentFinding(app)
		findings = appendFindingIfPresent(findings, finding, found)
		finding, found = buildSymlinkedEnvironmentFinding(app)
		findings = appendFindingIfPresent(findings, finding, found)
		finding, found = buildRuntimeOwnedEnvironmentFinding(app, runtimeIdentities)
		findings = appendFindingIfPresent(findings, finding, found)
		finding, found = buildRuntimeOwnedProjectRootFinding(app, runtimeIdentities)
		findings = appendFindingIfPresent(findings, finding, found)
		finding, found = buildRuntimeWritableSensitivePathsFinding(app, runtimeIdentities)
		findings = appendFindingIfPresent(findings, finding, found)
		finding, found = buildOverPermissiveNormalPathsFinding(app)
		findings = appendFindingIfPresent(findings, finding, found)
		finding, found = buildWritablePathBaselineFinding(app, runtimeIdentities)
		findings = appendFindingIfPresent(findings, finding, found)
	}

	return model.CheckResult{Findings: findings}, nil
}

func buildWorldWritablePathsFinding(app model.LaravelApp) (model.Finding, bool) {
	worldWritableRecords := []model.PathRecord{}
	criticalSeverity := false

	for _, pathRecord := range app.KeyPaths {
		if !pathRecord.IsWorldWritable() {
			continue
		}

		worldWritableRecords = append(worldWritableRecords, pathRecord)
		if pathRecord.RelativePath == ".env" {
			criticalSeverity = true
		}
	}

	if len(worldWritableRecords) == 0 {
		return model.Finding{}, false
	}

	evidence, affected := collectPathEvidenceAndTargets(app, worldWritableRecords)

	severity := model.SeverityHigh
	title := "Sensitive Laravel paths are world-writable"
	why := "World-writable code or configuration lets any local account change application behavior, code, or secrets."
	remediation := "Remove world-write permissions from the affected paths and keep writable access limited to the intended deploy or runtime identities."
	if criticalSeverity {
		severity = model.SeverityCritical
		title = ".env or other sensitive Laravel paths are world-writable"
		why = "A world-writable .env or code path lets untrusted local users or a compromised process change secrets and execution behavior directly."
		remediation = "Make .env writable only by the intended deploy or root identity and remove world-write permissions from all application paths."
	}

	return model.Finding{
		ID:          buildFindingID(filesystemPermissionsCheckID, "world_writable_paths", app.RootPath),
		CheckID:     filesystemPermissionsCheckID,
		Class:       model.FindingClassDirect,
		Severity:    severity,
		Confidence:  model.ConfidenceConfirmed,
		Title:       title,
		Why:         why,
		Remediation: remediation,
		Evidence:    evidence,
		Affected:    affected,
	}, true
}

func buildWorldReadableEnvironmentFinding(app model.LaravelApp) (model.Finding, bool) {
	envPath, found := app.PathRecord(".env")
	if !found || !envPath.IsWorldReadable() {
		return model.Finding{}, false
	}

	return model.Finding{
		ID:          buildFindingID(filesystemPermissionsCheckID, "world_readable_env", envPath.AbsolutePath),
		CheckID:     filesystemPermissionsCheckID,
		Class:       model.FindingClassDirect,
		Severity:    model.SeverityHigh,
		Confidence:  model.ConfidenceConfirmed,
		Title:       ".env is world-readable",
		Why:         "A world-readable .env can expose database credentials, app keys, and third-party secrets to unintended local users.",
		Remediation: "Restrict .env to the deploy or root owner and only the minimum group read access required by the runtime.",
		Evidence:    pathEvidence(envPath),
		Affected: []model.Target{
			pathTarget(envPath),
		},
	}, true
}

func buildSymlinkedEnvironmentFinding(app model.LaravelApp) (model.Finding, bool) {
	envPath, found := app.PathRecord(".env")
	if !found || !envPath.Inspected || !envPath.Exists || !envPath.IsSymlink() {
		return model.Finding{}, false
	}
	if symlinkedEnvironmentPathLooksExpected(app, envPath) {
		return model.Finding{}, false
	}

	evidence := pathEvidence(envPath)
	if envPath.ResolvedPath == "" {
		evidence = append(evidence, model.Evidence{Label: "note", Detail: ".env is a symlink"})
	}

	return model.Finding{
		ID:          buildFindingID(filesystemPermissionsCheckID, "symlinked_env", envPath.AbsolutePath),
		CheckID:     filesystemPermissionsCheckID,
		Class:       model.FindingClassHeuristic,
		Severity:    model.SeverityMedium,
		Confidence:  model.ConfidenceProbable,
		Title:       ".env symlink points outside the expected app deployment boundary",
		Why:         "Symlinked environment files are easy to mispoint during deploys and can hide secret exposure outside the expected application boundary.",
		Remediation: "Prefer a directly managed .env file at the app root, or document and tightly control the symlink target and its permissions.",
		Evidence:    evidence,
		Affected: []model.Target{
			pathTarget(envPath),
		},
	}, true
}

func symlinkedEnvironmentPathLooksExpected(app model.LaravelApp, envPath model.PathRecord) bool {
	if envPath.ResolvedPath == "" {
		return false
	}

	for _, appRoot := range appCanonicalRoots(app) {
		if strings.HasPrefix(envPath.ResolvedPath, appRoot+string(filepath.Separator)) {
			return true
		}
	}

	if app.Deployment.UsesReleaseLayout && app.Deployment.SharedPath != "" {
		sharedPathPrefix := filepath.Clean(app.Deployment.SharedPath) + string(filepath.Separator)
		return strings.HasPrefix(filepath.Clean(envPath.ResolvedPath), sharedPathPrefix)
	}

	return false
}

func buildRuntimeOwnedEnvironmentFinding(app model.LaravelApp, identities appRuntimeIdentities) (model.Finding, bool) {
	envPath, found := app.PathRecord(".env")
	if !found || !envPath.Inspected || !envPath.Exists {
		return model.Finding{}, false
	}

	envOwner := strings.TrimSpace(envPath.OwnerName)
	if envOwner == "" || !containsString(identities.Users, envOwner) {
		return model.Finding{}, false
	}

	evidence := append(pathEvidence(envPath),
		model.Evidence{Label: "runtime_user", Detail: envOwner},
	)

	return model.Finding{
		ID:          buildFindingID(filesystemPermissionsCheckID, "runtime_owned_env", envPath.AbsolutePath),
		CheckID:     filesystemPermissionsCheckID,
		Class:       model.FindingClassDirect,
		Severity:    model.SeverityHigh,
		Confidence:  model.ConfidenceConfirmed,
		Title:       ".env is owned by a Laravel runtime identity",
		Why:         "When the web or worker runtime owns .env, an application compromise or routine runtime write path can turn into direct secret and configuration tampering.",
		Remediation: "Keep .env owned by the deploy or root identity and ensure the runtime only has the minimum read access required.",
		Evidence:    evidence,
		Affected: []model.Target{
			appTarget(app),
			pathTarget(envPath),
		},
	}, true
}

func buildRuntimeOwnedProjectRootFinding(app model.LaravelApp, identities appRuntimeIdentities) (model.Finding, bool) {
	rootRecord := app.RootRecord
	if !rootRecord.Inspected || !rootRecord.Exists {
		return model.Finding{}, false
	}

	rootOwner := strings.TrimSpace(rootRecord.OwnerName)
	if rootOwner == "" || !containsString(identities.Users, rootOwner) {
		return model.Finding{}, false
	}

	evidence := append(pathEvidence(rootRecord), model.Evidence{Label: "runtime_user", Detail: rootOwner})

	return model.Finding{
		ID:          buildFindingID(filesystemPermissionsCheckID, "runtime_owned_project_root", app.RootPath),
		CheckID:     filesystemPermissionsCheckID,
		Class:       model.FindingClassDirect,
		Severity:    model.SeverityHigh,
		Confidence:  model.ConfidenceConfirmed,
		Title:       "Laravel project root is owned by a runtime identity",
		Why:         "When the deployed app tree is owned by the web or worker runtime user, ordinary application compromise or drifted maintenance tasks can rewrite code and configuration much more easily.",
		Remediation: "Keep the project tree owned by the deploy identity, not the runtime identity, and reserve runtime write access for storage/ and bootstrap/cache/ only.",
		Evidence:    evidence,
		Affected: []model.Target{
			appTarget(app),
			pathTarget(rootRecord),
		},
	}, true
}

func buildRuntimeWritableSensitivePathsFinding(app model.LaravelApp, identities appRuntimeIdentities) (model.Finding, bool) {
	if len(identities.Users) == 0 && len(identities.Groups) == 0 {
		return model.Finding{}, false
	}

	writablePaths := []model.PathRecord{}
	severity := model.SeverityHigh

	for _, relativePath := range sensitiveRuntimeBoundaryPaths() {
		pathRecord, found := app.PathRecord(relativePath)
		if !found || !pathWritableByRuntimeIdentity(pathRecord, identities) {
			continue
		}

		if relativePath == ".env" || relativePath == "public/index.php" || relativePath == "composer.json" || relativePath == "composer.lock" {
			severity = model.SeverityCritical
		}
		writablePaths = append(writablePaths, pathRecord)
	}

	if len(writablePaths) == 0 {
		return model.Finding{}, false
	}

	evidence := runtimeIdentityEvidence(identities)
	pathEvidence, affected := collectPathEvidenceAndTargets(app, writablePaths)
	evidence = append(evidence, pathEvidence...)

	return model.Finding{
		ID:          buildFindingID(filesystemPermissionsCheckID, "runtime_writable_sensitive_paths", app.RootPath),
		CheckID:     filesystemPermissionsCheckID,
		Class:       model.FindingClassDirect,
		Severity:    severity,
		Confidence:  model.ConfidenceConfirmed,
		Title:       "Laravel runtime identities can write code or configuration paths",
		Why:         "The PHP runtime should write only to storage/ and bootstrap/cache/. Write access to code, dependency, or environment paths weakens the deploy/runtime split and materially increases tampering risk after compromise.",
		Remediation: "Restrict runtime write access to storage/ and bootstrap/cache/ only, and keep app code, config, composer metadata, and .env read-only from runtime identities.",
		Evidence:    evidence,
		Affected:    affected,
	}, true
}

func buildOverPermissiveNormalPathsFinding(app model.LaravelApp) (model.Finding, bool) {
	evidence := []model.Evidence{}
	affected := []model.Target{appTarget(app)}
	broaderPaths := 0

	for _, pathRecord := range app.KeyPaths {
		if pathRecord.IsWorldWritable() {
			continue
		}
		if pathRecord.RelativePath == ".env" && pathRecord.IsWorldReadable() {
			continue
		}

		expectedMode, ok := expectedMaxModeForPath(pathRecord)
		if !ok || !pathModeExceeds(pathRecord, expectedMode) {
			continue
		}

		broaderPaths++
		evidence = append(evidence, pathEvidence(pathRecord)...)
		evidence = append(evidence, model.Evidence{Label: "expected_max_mode", Detail: expectedModeOctal(expectedMode)})
		affected = append(affected, pathTarget(pathRecord))
	}

	if broaderPaths == 0 {
		return model.Finding{}, false
	}

	return model.Finding{
		ID:          buildFindingID(filesystemPermissionsCheckID, "permission_shape_drift", app.RootPath),
		CheckID:     filesystemPermissionsCheckID,
		Class:       model.FindingClassDirect,
		Severity:    model.SeverityMedium,
		Confidence:  model.ConfidenceConfirmed,
		Title:       "Laravel path permissions exceed the hardened baseline",
		Why:         "Modes broader than the checklist baseline make it easier for local users, shared groups, or drifted deploys to widen access to Laravel code and secrets over time.",
		Remediation: "Keep normal directories at 0750 or stricter, normal files and .env at 0640 or stricter, and reserve broader write access for explicitly writable Laravel paths only.",
		Evidence:    evidence,
		Affected:    affected,
	}, true
}

func buildWritablePathBaselineFinding(app model.LaravelApp, identities appRuntimeIdentities) (model.Finding, bool) {
	evidence := runtimeIdentityEvidence(identities)
	affected := []model.Target{appTarget(app)}
	issues := 0

	for _, relativePath := range writableRuntimePaths() {
		pathRecord, found := app.PathRecord(relativePath)
		if !found || !pathRecord.Inspected || !pathRecord.Exists {
			continue
		}

		expectedMode, hasExpectedMode := expectedMaxModeForPath(pathRecord)
		if hasExpectedMode && pathModeExceeds(pathRecord, expectedMode) {
			issues++
			evidence = append(evidence, pathEvidence(pathRecord)...)
			evidence = append(evidence, model.Evidence{Label: "expected_max_mode", Detail: expectedModeOctal(expectedMode)})
			affected = append(affected, pathTarget(pathRecord))
			continue
		}

		if len(identities.Users) == 0 && len(identities.Groups) == 0 {
			continue
		}
		if pathWritableByRuntimeIdentity(pathRecord, identities) {
			continue
		}

		issues++
		evidence = append(evidence, pathEvidence(pathRecord)...)
		evidence = append(evidence, model.Evidence{Label: "expected_runtime_access", Detail: "runtime-writable"})
		affected = append(affected, pathTarget(pathRecord))
	}

	if issues == 0 {
		return model.Finding{}, false
	}

	return model.Finding{
		ID:          buildFindingID(filesystemPermissionsCheckID, "writable_path_baseline", app.RootPath),
		CheckID:     filesystemPermissionsCheckID,
		Class:       model.FindingClassDirect,
		Severity:    model.SeverityMedium,
		Confidence:  model.ConfidenceConfirmed,
		Title:       "Writable Laravel paths do not match the hardened writable baseline",
		Why:         "Laravel should have a very small writable surface. When storage/ or bootstrap/cache/ are either not runtime-writable or broader than necessary, the deployment model becomes both fragile and harder to audit.",
		Remediation: "Keep storage/ and bootstrap/cache/ runtime-writable, but limit them to 0770 directories and 0660 files or a stricter justified equivalent.",
		Evidence:    evidence,
		Affected:    affected,
	}, true
}

func sensitiveRuntimeBoundaryPaths() []string {
	return []string{
		"app",
		"bootstrap",
		"config",
		"database",
		"resources",
		"routes",
		"vendor",
		"public/index.php",
		"composer.json",
		"composer.lock",
		".env",
	}
}

func writableRuntimePaths() []string {
	return []string{
		"storage",
		"storage/logs",
		"bootstrap/cache",
		"bootstrap/cache/config.php",
	}
}

func expectedMaxModeForPath(pathRecord model.PathRecord) (uint32, bool) {
	switch pathRecord.RelativePath {
	case "storage", "storage/logs", "bootstrap/cache":
		return 0o770, true
	case "bootstrap/cache/config.php":
		return 0o660, true
	case "public/storage":
		return 0, false
	case ".env":
		return 0o640, true
	}

	switch pathRecord.EffectiveKind() {
	case model.PathKindDirectory:
		return 0o750, true
	case model.PathKindFile:
		return 0o640, true
	default:
		return 0, false
	}
}

func pathModeExceeds(pathRecord model.PathRecord, expectedMaxMode uint32) bool {
	if !pathRecord.Inspected || !pathRecord.Exists {
		return false
	}

	return pathRecord.Permissions&^expectedMaxMode != 0
}

func expectedModeOctal(mode uint32) string {
	return fmt.Sprintf("%04o", mode)
}

func runtimeIdentityEvidence(identities appRuntimeIdentities) []model.Evidence {
	evidence := []model.Evidence{}
	if len(identities.Users) > 0 {
		evidence = append(evidence, model.Evidence{Label: "runtime_users", Detail: strings.Join(identities.Users, ", ")})
	}
	if len(identities.Groups) > 0 {
		evidence = append(evidence, model.Evidence{Label: "runtime_groups", Detail: strings.Join(identities.Groups, ", ")})
	}

	return evidence
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}

	return false
}

func appendFindingIfPresent(findings []model.Finding, finding model.Finding, found bool) []model.Finding {
	if !found {
		return findings
	}

	return append(findings, finding)
}

func collectPathEvidenceAndTargets(app model.LaravelApp, pathRecords []model.PathRecord) ([]model.Evidence, []model.Target) {
	evidence := []model.Evidence{}
	affected := []model.Target{appTarget(app)}

	for _, pathRecord := range pathRecords {
		evidence = append(evidence, pathEvidence(pathRecord)...)
		affected = append(affected, pathTarget(pathRecord))
	}

	return evidence, affected
}
