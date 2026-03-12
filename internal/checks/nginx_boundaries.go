package checks

import (
	"context"
	"strings"

	"github.com/nagi1/larainspect/internal/model"
)

const nginxBoundaryCheckID = "nginx.boundaries"

type NginxBoundaryCheck struct{}

func init() {
	MustRegister(NginxBoundaryCheck{})
}

func (NginxBoundaryCheck) ID() string {
	return nginxBoundaryCheckID
}

func (NginxBoundaryCheck) Run(_ context.Context, _ model.ExecutionContext, snapshot model.Snapshot) (model.CheckResult, error) {
	findings := []model.Finding{}

	for _, app := range snapshot.Apps {
		for _, site := range nginxSitesForApp(app, snapshot.NginxSites) {
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
		Title:       "Project root is served as the Nginx docroot",
		Why:         "Serving the Laravel project root instead of public/ risks exposing .env, source code, cached config, backups, and other non-public files.",
		Remediation: "Point the Nginx root at the Laravel public/ directory only and keep all private application files outside the served document root.",
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
		Title:       "Nginx allows generic PHP execution under the app docroot",
		Why:         "A generic .php location makes dropped PHP files under public paths executable instead of limiting execution to the intended front controller.",
		Remediation: "Restrict PHP handling to the front controller and ensure arbitrary .php files under public, upload, or storage-adjacent paths are never executed.",
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
		Title:       "Nginx config is missing explicit deny rules for hidden or sensitive files",
		Why:         "Without explicit deny rules, dotfiles, environment backups, VCS metadata, or other sensitive artifacts are easier to expose through routing mistakes or future file drift.",
		Remediation: "Add explicit deny rules for hidden files, .env variants, VCS paths, and common backup or dump artifacts in the Laravel site config.",
		Evidence:    evidence,
		Affected: []model.Target{
			appTarget(app),
			{Type: "path", Path: site.ConfigPath},
		},
	}, true
}

func buildUploadExecutionFinding(app model.LaravelApp, site model.NginxSite) (model.Finding, bool) {
	publicStoragePath, hasPublicStorage := app.PathRecord("public/storage")
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
		Title:       "Nginx can execute PHP in upload or storage-adjacent public paths",
		Why:         "Upload and storage-adjacent public paths must not execute PHP because they become straightforward code-execution targets after file upload or file-write drift.",
		Remediation: "Block PHP execution in upload and public/storage paths and keep generic PHP handling away from any storage-adjacent or user-controlled directories.",
		Evidence:    evidence,
		Affected: []model.Target{
			appTarget(app),
			{Type: "path", Path: site.ConfigPath},
		},
	}, true
}
