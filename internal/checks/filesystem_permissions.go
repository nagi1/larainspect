package checks

import (
	"context"
	"path/filepath"
	"strings"

	"github.com/nagi1/larainspect/internal/model"
)

const filesystemPermissionsCheckID = "filesystem.permissions"

type FilesystemPermissionsCheck struct{}

func init() {
	MustRegister(FilesystemPermissionsCheck{})
}

func (FilesystemPermissionsCheck) ID() string {
	return filesystemPermissionsCheckID
}

func (FilesystemPermissionsCheck) Run(_ context.Context, _ model.ExecutionContext, snapshot model.Snapshot) (model.CheckResult, error) {
	findings := []model.Finding{}

	for _, app := range snapshot.Apps {
		if worldWritableFinding, found := buildWorldWritablePathsFinding(app); found {
			findings = append(findings, worldWritableFinding)
		}

		if worldReadableEnvFinding, found := buildWorldReadableEnvironmentFinding(app); found {
			findings = append(findings, worldReadableEnvFinding)
		}

		if symlinkedEnvFinding, found := buildSymlinkedEnvironmentFinding(app); found {
			findings = append(findings, symlinkedEnvFinding)
		}
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

	evidence := []model.Evidence{}
	affected := []model.Target{appTarget(app)}
	for _, pathRecord := range worldWritableRecords {
		evidence = append(evidence, pathEvidence(pathRecord)...)
		affected = append(affected, pathTarget(pathRecord))
	}

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
