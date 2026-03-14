package checks

import (
	"context"
	"path/filepath"
	"strings"

	"github.com/nagi1/larainspect/internal/model"
)

const nginxBoundaryCheckID = "nginx.boundaries"

var _ Check = NginxBoundaryCheck{}

type NginxBoundaryCheck struct{}

func init() {
	MustRegister(NginxBoundaryCheck{})
}

func (NginxBoundaryCheck) ID() string {
	return nginxBoundaryCheckID
}

func (NginxBoundaryCheck) Description() string {
	return "Inspect Nginx boundaries around Laravel public entrypoints."
}

func (NginxBoundaryCheck) Run(_ context.Context, _ model.ExecutionContext, snapshot model.Snapshot) (model.CheckResult, error) {
	findings := []model.Finding{}

	for _, app := range snapshot.Apps {
		matchedSites := nginxSitesForApp(app, snapshot.NginxSites)

		if publicStorageExposureFinding, found := buildPublicStorageExposureFinding(app, matchedSites); found {
			findings = append(findings, publicStorageExposureFinding)
		}
		if publicStorageSymlinkFinding, found := buildUnexpectedPublicStorageSymlinkFinding(app); found {
			findings = append(findings, publicStorageSymlinkFinding)
		}
		findings = append(findings, buildUnexpectedPublicSymlinkFindings(app)...)
		if publicPHPFinding, found := buildUnexpectedPublicPHPFinding(app, matchedSites); found {
			findings = append(findings, publicPHPFinding)
		}

		for _, site := range matchedSites {
			if projectRootServedFinding, found := buildProjectRootServedFinding(app, site); found {
				findings = append(findings, projectRootServedFinding)
			}

			if genericPHPFinding, found := buildGenericPHPExecutionFinding(app, site); found {
				findings = append(findings, genericPHPFinding)
			}

			if missingDenyRulesFinding, found := buildMissingDenyRulesFinding(app, site); found {
				findings = append(findings, missingDenyRulesFinding)
			}

			if uploadExecutionFinding, found := buildUploadExecutionFinding(app, site); found {
				findings = append(findings, uploadExecutionFinding)
			}
		}
	}

	return model.CheckResult{Findings: findings}, nil
}

func nginxSitesForApp(app model.LaravelApp, nginxSites []model.NginxSite) []model.NginxSite {
	matchedSites := []model.NginxSite{}

	for _, site := range nginxSites {
		if !appOwnsServedRoot(app, site.Root) {
			continue
		}

		matchedSites = append(matchedSites, site)
	}

	return matchedSites
}

func buildUnexpectedPublicPHPFinding(app model.LaravelApp, matchedSites []model.NginxSite) (model.Finding, bool) {
	publicPHPArtifacts := publicNonUploadPHPArtifacts(app)
	if len(publicPHPArtifacts) == 0 || len(matchedSites) == 0 {
		return model.Finding{}, false
	}

	severity := model.SeverityMedium
	confidence := model.ConfidenceProbable
	title := "Served public tree contains PHP files beyond the Laravel front controller"
	why := "Extra PHP files under the served public tree increase the chance that a dropped webshell, probe, or forgotten maintenance script becomes reachable if the web boundary drifts or allows generic PHP handling."
	remediation := "Keep only the intended front controller under public/ where practical, remove unexpected PHP files, and restrict Nginx PHP handling to /index.php only."
	phpBoundary := "front-controller-only PHP handling detected"

	if anySiteAllowsGenericPHPExecution(matchedSites) {
		severity = model.SeverityHigh
		confidence = model.ConfidenceConfirmed
		title = "Served public tree contains PHP files that Nginx may execute directly"
		why = "Dropped PHP files under the served public tree can execute as webshells or maintenance backdoors when the site allows generic PHP handling instead of limiting execution to the Laravel front controller."
		phpBoundary = "generic PHP handling present"
	}

	evidence := []model.Evidence{{Label: "php_boundary", Detail: phpBoundary}}
	affected := []model.Target{appTarget(app)}
	for _, site := range matchedSites {
		evidence = append(evidence, model.Evidence{Label: "config", Detail: site.ConfigPath})
		affected = append(affected, model.Target{Type: "path", Path: site.ConfigPath})
	}
	for _, artifact := range publicPHPArtifacts {
		evidence = append(evidence, pathEvidence(artifact.Path)...)
		affected = append(affected, pathTarget(artifact.Path))
	}

	return model.Finding{
		ID:          buildFindingID(nginxBoundaryCheckID, "unexpected_public_php", app.RootPath),
		CheckID:     nginxBoundaryCheckID,
		Class:       model.FindingClassDirect,
		Severity:    severity,
		Confidence:  confidence,
		Title:       title,
		Why:         why,
		Remediation: remediation,
		Evidence:    evidence,
		Affected:    affected,
	}, true
}

func buildProjectRootServedFinding(app model.LaravelApp, site model.NginxSite) (model.Finding, bool) {
	if !appOwnsServedRoot(app, site.Root) || appUsesPublicRoot(app, site.Root) {
		return model.Finding{}, false
	}

	return model.Finding{
		ID:          buildFindingID(nginxBoundaryCheckID, "project_root_served", site.ConfigPath),
		CheckID:     nginxBoundaryCheckID,
		Class:       model.FindingClassDirect,
		Severity:    model.SeverityCritical,
		Confidence:  model.ConfidenceConfirmed,
		Title:       "Nginx is serving the Laravel project root instead of public/",
		Why:         "When the web root points at the whole project instead of public/, files such as .env, source code, backups, and cached config are much easier to expose.",
		Remediation: "Set the Nginx root to the app's public/ directory only and keep all private Laravel files outside the served web root.",
		Evidence: []model.Evidence{
			{Label: "config", Detail: site.ConfigPath},
			{Label: "root", Detail: site.Root},
		},
		Affected: []model.Target{
			appTarget(app),
			{Type: "path", Path: site.ConfigPath},
		},
	}, true
}

func buildGenericPHPExecutionFinding(app model.LaravelApp, site model.NginxSite) (model.Finding, bool) {
	if !site.HasGenericPHPLocation {
		return model.Finding{}, false
	}

	evidence := []model.Evidence{
		{Label: "config", Detail: site.ConfigPath},
		{Label: "root", Detail: site.Root},
	}
	if len(site.GenericPHPLocations) > 0 {
		evidence = append(evidence, model.Evidence{Label: "location", Detail: strings.Join(site.GenericPHPLocations, ", ")})
	}
	if len(site.FrontControllerPaths) > 0 {
		evidence = append(evidence, model.Evidence{Label: "front_controller", Detail: strings.Join(site.FrontControllerPaths, ", ")})
	}

	return model.Finding{
		ID:          buildFindingID(nginxBoundaryCheckID, "generic_php_execution", site.ConfigPath),
		CheckID:     nginxBoundaryCheckID,
		Class:       model.FindingClassDirect,
		Severity:    model.SeverityHigh,
		Confidence:  model.ConfidenceConfirmed,
		Title:       "Nginx can run any PHP file in the public site directory",
		Why:         "This means a stray or uploaded .php file under the served directory may run as code instead of being downloaded or blocked.",
		Remediation: "Route PHP execution only through the intended front controller, and block direct execution of arbitrary .php files in public, upload, and storage-adjacent paths.",
		Evidence:    evidence,
		Affected: []model.Target{
			appTarget(app),
			{Type: "path", Path: site.ConfigPath},
		},
	}, true
}

func buildMissingDenyRulesFinding(app model.LaravelApp, site model.NginxSite) (model.Finding, bool) {
	if site.HiddenFilesDenied && site.SensitiveFilesDenied {
		return model.Finding{}, false
	}

	evidence := []model.Evidence{
		{Label: "config", Detail: site.ConfigPath},
		{Label: "root", Detail: site.Root},
	}

	if !site.HiddenFilesDenied {
		evidence = append(evidence, model.Evidence{Label: "missing_deny", Detail: "hidden files such as dotfiles are not explicitly denied"})
	}
	if !site.SensitiveFilesDenied {
		evidence = append(evidence, model.Evidence{Label: "missing_deny", Detail: "sensitive files such as .env, VCS metadata, or backup artifacts are not explicitly denied"})
	}

	return model.Finding{
		ID:          buildFindingID(nginxBoundaryCheckID, "missing_deny_rules", site.ConfigPath),
		CheckID:     nginxBoundaryCheckID,
		Class:       model.FindingClassDirect,
		Severity:    model.SeverityHigh,
		Confidence:  model.ConfidenceProbable,
		Title:       "Nginx is not explicitly blocking hidden or sensitive files",
		Why:         "Without explicit deny rules, files like .env, backups, or version-control metadata are easier to expose after a routing mistake or deploy drift.",
		Remediation: "Add deny rules for hidden files, .env variants, version-control directories, and common backup or dump files in the site config.",
		Evidence:    evidence,
		Affected: []model.Target{
			appTarget(app),
			{Type: "path", Path: site.ConfigPath},
		},
	}, true
}

func buildUploadExecutionFinding(app model.LaravelApp, site model.NginxSite) (model.Finding, bool) {
	publicStoragePath, hasPublicStorage := appPublicStoragePath(app)
	if !site.UploadExecutionAllowed && !(site.HasGenericPHPLocation && hasPublicStorage && publicStoragePath.Exists) {
		return model.Finding{}, false
	}

	evidence := []model.Evidence{
		{Label: "config", Detail: site.ConfigPath},
	}
	if len(site.UploadExecutionMatchers) > 0 {
		evidence = append(evidence, model.Evidence{Label: "location", Detail: strings.Join(site.UploadExecutionMatchers, ", ")})
	}
	if hasPublicStorage && publicStoragePath.Exists {
		evidence = append(evidence, model.Evidence{Label: "path", Detail: publicStoragePath.AbsolutePath})
	}

	return model.Finding{
		ID:          buildFindingID(nginxBoundaryCheckID, "upload_execution", site.ConfigPath),
		CheckID:     nginxBoundaryCheckID,
		Class:       model.FindingClassDirect,
		Severity:    model.SeverityHigh,
		Confidence:  model.ConfidenceProbable,
		Title:       "Nginx can run PHP from upload or public storage paths",
		Why:         "If user-controlled or storage-backed directories can execute PHP, a bad upload or stray file can turn into remote code execution.",
		Remediation: "Block PHP execution in upload and public storage directories and keep generic PHP handling away from any user-controlled path.",
		Evidence:    evidence,
		Affected: []model.Target{
			appTarget(app),
			{Type: "path", Path: site.ConfigPath},
		},
	}, true
}

func publicNonUploadPHPArtifacts(app model.LaravelApp) []model.ArtifactRecord {
	artifacts := []model.ArtifactRecord{}
	for _, artifact := range app.Artifacts {
		if artifact.Kind != model.ArtifactKindPublicPHPFile || !artifact.WithinPublicPath || artifact.UploadLikePath {
			continue
		}

		artifacts = append(artifacts, artifact)
	}

	return artifacts
}

func anySiteAllowsGenericPHPExecution(sites []model.NginxSite) bool {
	for _, site := range sites {
		if site.HasGenericPHPLocation {
			return true
		}
	}

	return false
}

func buildPublicStorageExposureFinding(app model.LaravelApp, matchedSites []model.NginxSite) (model.Finding, bool) {
	publicStoragePath, found := appExpectedPublicStorageSymlink(app)
	if !found {
		return model.Finding{}, false
	}

	summary := summarizePublicStorageBoundary(app, matchedSites)
	evidence := append(pathEvidence(publicStoragePath), summary.evidence...)
	affected := append([]model.Target{
		appTarget(app),
		pathTarget(publicStoragePath),
	}, summary.affected...)

	return model.Finding{
		ID:          buildFindingID(nginxBoundaryCheckID, "public_storage_exposure", publicStoragePath.AbsolutePath),
		CheckID:     nginxBoundaryCheckID,
		Class:       model.FindingClassDirect,
		Severity:    summary.severity,
		Confidence:  summary.confidence,
		Title:       summary.title,
		Why:         summary.why,
		Remediation: "Keep only intentionally public assets on the public disk, store untrusted uploads on a non-public disk when possible, and verify Nginx never executes PHP from public/storage or upload-like paths.",
		Evidence:    evidence,
		Affected:    affected,
	}, true
}

type publicStorageBoundarySummary struct {
	title      string
	why        string
	severity   model.Severity
	confidence model.Confidence
	evidence   []model.Evidence
	affected   []model.Target
}

func summarizePublicStorageBoundary(app model.LaravelApp, matchedSites []model.NginxSite) publicStorageBoundarySummary {
	summary := publicStorageBoundarySummary{
		title:      "public/storage symlink exists and should be reviewed as a public boundary",
		why:        "Laravel's storage:link pattern intentionally exposes the public disk through a symlink under public/, so operators should review which files are written there and whether the served web boundary makes that exposure intentional.",
		severity:   model.SeverityInformational,
		confidence: model.ConfidenceConfirmed,
		evidence: []model.Evidence{{
			Label:  "exposure",
			Detail: "Laravel public-disk files are exposed through the public/storage symlink when the app public directory is served.",
		}},
	}
	if len(matchedSites) == 0 {
		summary.evidence = append(summary.evidence, model.Evidence{
			Label:  "note",
			Detail: "No matched Nginx site was discovered for this app, so Larainspect could not confirm how the public directory is served from host config.",
		})
		return summary
	}

	configPaths := make([]string, 0, len(matchedSites))
	roots := make([]string, 0, len(matchedSites))
	phpBoundary := "front-controller only"
	publicRootConfirmed := false

	for _, site := range matchedSites {
		configPaths = append(configPaths, site.ConfigPath)
		roots = append(roots, site.Root)
		summary.affected = append(summary.affected, model.Target{Type: "path", Path: site.ConfigPath})
		if site.HasGenericPHPLocation || site.UploadExecutionAllowed {
			phpBoundary = "generic or upload-adjacent PHP handling present"
		}
		if appUsesPublicRoot(app, site.Root) {
			publicRootConfirmed = true
		}
	}

	summary.evidence = append(summary.evidence,
		model.Evidence{Label: "config", Detail: strings.Join(configPaths, ", ")},
		model.Evidence{Label: "root", Detail: strings.Join(roots, ", ")},
		model.Evidence{Label: "php_boundary", Detail: phpBoundary},
	)

	if publicRootConfirmed {
		summary.title = "public/storage exposes Laravel public-disk files through the web root"
		summary.why = "Laravel's storage:link pattern intentionally makes files on the public disk reachable under the served public directory, so uploads or generated assets placed there are public by design and should be reviewed as an explicit exposure boundary."
		summary.severity = model.SeverityLow
		return summary
	}

	summary.title = "public/storage exists inside a served Laravel tree"
	summary.why = "The public/storage symlink exists and Larainspect found a served Laravel site for this app, but the docroot is not the expected public/ path. Review how that server layout exposes the symlinked files and whether the broader boundary is intentional."
	summary.severity = model.SeverityLow

	return summary
}

func buildUnexpectedPublicStorageSymlinkFinding(app model.LaravelApp) (model.Finding, bool) {
	publicStoragePath, found := appPublicStoragePath(app)
	if !found {
		return model.Finding{}, false
	}
	if strings.TrimSpace(publicStoragePath.ResolvedPath) == "" {
		return model.Finding{}, false
	}
	if publicStorageSymlinkLooksExpected(app, publicStoragePath) {
		return model.Finding{}, false
	}

	return model.Finding{
		ID:          buildFindingID(nginxBoundaryCheckID, "unexpected_public_storage_symlink", publicStoragePath.AbsolutePath),
		CheckID:     nginxBoundaryCheckID,
		Class:       model.FindingClassDirect,
		Severity:    model.SeverityHigh,
		Confidence:  model.ConfidenceConfirmed,
		Title:       "public/storage points outside the expected Laravel public storage target",
		Why:         "A public symlink that resolves outside storage/app/public can expose private files, shared secrets, or unrelated release content directly through the web root.",
		Remediation: "Keep public/storage pointed only at storage/app/public or an intentional shared equivalent such as shared/storage/app/public in a release layout.",
		Evidence:    pathEvidence(publicStoragePath),
		Affected: []model.Target{
			appTarget(app),
			pathTarget(publicStoragePath),
		},
	}, true
}

func buildUnexpectedPublicSymlinkFindings(app model.LaravelApp) []model.Finding {
	findings := []model.Finding{}

	for _, artifact := range app.Artifacts {
		if artifact.Kind != model.ArtifactKindPublicSymlink {
			continue
		}

		if artifact.Path.RelativePath == "public/storage" {
			continue
		}

		finding, found := buildUnexpectedPublicSymlinkFinding(app, artifact.Path)
		if !found {
			continue
		}

		findings = append(findings, finding)
	}

	return findings
}

func buildUnexpectedPublicSymlinkFinding(app model.LaravelApp, pathRecord model.PathRecord) (model.Finding, bool) {
	if !pathRecord.Inspected || !pathRecord.Exists || !pathRecord.IsSymlink() {
		return model.Finding{}, false
	}
	if strings.TrimSpace(pathRecord.ResolvedPath) == "" || !publicSymlinkTargetsPrivateAppPath(app, pathRecord) {
		return model.Finding{}, false
	}

	return model.Finding{
		ID:          buildFindingID(nginxBoundaryCheckID, "private_public_symlink", pathRecord.AbsolutePath),
		CheckID:     nginxBoundaryCheckID,
		Class:       model.FindingClassDirect,
		Severity:    model.SeverityHigh,
		Confidence:  model.ConfidenceConfirmed,
		Title:       "A public symlink resolves into a private Laravel path",
		Why:         "A symlink under public/ that resolves into non-public application or shared paths can expose private files directly through the web root.",
		Remediation: "Keep public symlinks limited to intentionally public assets only and never point them at private Laravel code, config, storage, or shared secrets.",
		Evidence:    pathEvidence(pathRecord),
		Affected: []model.Target{
			appTarget(app),
			pathTarget(pathRecord),
		},
	}, true
}

func publicSymlinkTargetsPrivateAppPath(app model.LaravelApp, pathRecord model.PathRecord) bool {
	resolvedTarget := filepath.Clean(pathRecord.ResolvedPath)
	if pathIsWithinAnyRoot(resolvedTarget, appExpectedPublicStorageTargets(app)) {
		return false
	}

	privateRoots := []string{}
	for _, appRoot := range appCanonicalRoots(app) {
		privateRoots = append(privateRoots, appRoot)
	}
	if strings.TrimSpace(app.Deployment.SharedPath) != "" {
		privateRoots = append(privateRoots, app.Deployment.SharedPath)
	}

	return pathIsWithinAnyRoot(resolvedTarget, privateRoots)
}
