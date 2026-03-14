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
	title := "Sensitive Laravel paths can be changed by any local user"
	why := "If code or configuration is world-writable, any local account or compromised process on the server can change app behavior, code, or secrets."
	remediation := "Remove world-write permissions and keep write access limited to the specific deploy or runtime user that actually needs it."
	if criticalSeverity {
		severity = model.SeverityCritical
		title = "Any local user can change .env or other critical app files"
		why = "If .env or core code paths are world-writable, secrets and execution behavior can be changed directly, turning a local foothold into full app compromise."
		remediation = "Make .env and core app files writable only by the intended deploy or root user, and remove world-write access from the rest of the app tree."
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
		Title:       ".env can be read by any local user",
		Why:         "If .env is world-readable, any local user on the server may be able to read database passwords, app keys, and other secrets.",
		Remediation: "Limit .env read access to the deploy or root owner and only the minimum group access the runtime actually needs.",
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
		Title:       ".env symlink points somewhere unexpected",
		Why:         "A symlinked .env file is easy to point at the wrong target during deploys, which can expose or mix up secrets.",
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
		Title:       ".env is owned by the web or worker user",
		Why:         "If the web server or queue worker user owns .env, an app compromise can change secrets and configuration more easily.",
		Remediation: "Keep .env owned by the deploy or root user and give the runtime only the minimum read access it needs.",
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
		Title:       "App directory is owned by the web or worker user",
		Why:         "If the runtime user owns the whole app directory, a compromise in the app can rewrite code and configuration much more easily.",
		Remediation: "Keep the app directory owned by the deploy user, not the runtime user, and reserve runtime write access for storage/ and bootstrap/cache/ only.",
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
		Title:       "Web or worker user can change app code or config",
		Why:         "The PHP runtime should usually write only to storage/ and bootstrap/cache/. If it can also write code, config, or .env, a compromise can tamper with the app much more easily.",
		Remediation: "Restrict runtime write access to storage/ and bootstrap/cache/ only, and keep app code, config, Composer files, and .env read-only for runtime users.",
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
		Title:       "Laravel file permissions are broader than needed",
		Why:         "When normal app files or directories are more open than expected, local users, shared groups, or deploy mistakes can widen access over time.",
		Remediation: "Keep normal directories owner-and-group only, keep normal files and .env owner-and-group readable only, and reserve broader access for the small set of paths Laravel must write to.",
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
		Title:       "Laravel writable directories do not match the expected safe setup",
		Why:         "Laravel should have only a small writable area. If storage/ or bootstrap/cache/ are not writable enough or are too open, the deployment becomes fragile and harder to trust.",
		Remediation: "Make storage/ and bootstrap/cache/ writable by the runtime, but keep them limited to owner-and-group write access rather than opening them more broadly.",
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
