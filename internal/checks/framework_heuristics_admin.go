package checks

import (
	"strings"

	"github.com/nagi1/larainspect/internal/model"
)

func buildAdminSurfaceHeuristicFindings(app model.LaravelApp) []model.Finding {
	findings := []model.Finding{}

	for _, definition := range riskyPackageExposureDefinitions() {
		packageFinding, found := buildRiskyPackageExposureFinding(app, definition)
		if !found {
			continue
		}

		findings = append(findings, packageFinding)
	}

	publicAdminToolArtifacts := []model.ArtifactRecord{}
	for _, artifact := range app.Artifacts {
		if artifact.Kind == model.ArtifactKindPublicAdminTool && artifact.WithinPublicPath {
			publicAdminToolArtifacts = append(publicAdminToolArtifacts, artifact)
		}
	}
	if len(publicAdminToolArtifacts) > 0 {
		findings = append(findings, buildHeuristicFindingForPublicAdminToolArtifacts(app, publicAdminToolArtifacts))
	}

	return findings
}

type riskyPackageExposureDefinition struct {
	PackageName       string
	Title             string
	Why               string
	Remediation       string
	HighWhenInstalled bool
}

func riskyPackageExposureDefinitions() []riskyPackageExposureDefinition {
	return []riskyPackageExposureDefinition{
		{
			PackageName:       "laravel/telescope",
			Title:             "Laravel Telescope is installed in this app",
			Why:               "If Telescope is reachable in production, it can reveal requests, queries, jobs, exceptions, and other internal app details.",
			Remediation:       "Make sure Telescope is disabled in production or locked behind strong operator-only access, and verify its dashboard is not public.",
			HighWhenInstalled: true,
		},
		{
			PackageName: "barryvdh/laravel-debugbar",
			Title:       "Laravel Debugbar is installed in this app",
			Why:         "If Debugbar is active in production, it can reveal SQL queries, routes, timing data, and exception details.",
			Remediation: "Keep Debugbar out of production builds or verify it is fully disabled and unreachable in the deployed app.",
		},
		{
			PackageName: "itsgoingd/clockwork",
			Title:       "Clockwork is installed in this app",
			Why:         "If Clockwork stays reachable in production, it can reveal request timelines, debug details, and configuration clues.",
			Remediation: "Verify Clockwork is not exposed in production, and tightly restrict any diagnostic routes or headers if it must be used.",
		},
		{
			PackageName: "spatie/laravel-ignition",
			Title:       "Ignition is installed in this app",
			Why:         "If Ignition or similar error pages are exposed in production, they can reveal stack traces, configuration clues, and exception details.",
			Remediation: "Verify production error handling does not expose Ignition debug pages and keep detailed exception tooling out of public reach.",
		},
	}
}

func buildRiskyPackageExposureFinding(app model.LaravelApp, definition riskyPackageExposureDefinition) (model.Finding, bool) {
	packageRecord, found := packageRecordForApp(app, definition.PackageName)
	if !found {
		return model.Finding{}, false
	}

	severity, confidence := packageExposureSeverityAndConfidence(packageRecord, definition.HighWhenInstalled)
	return buildHeuristicFindingForPackageRecord(
		definition.PackageName,
		app,
		packageRecord,
		severity,
		confidence,
		definition.Title,
		definition.Why,
		definition.Remediation,
	), true
}

func packageExposureSeverityAndConfidence(packageRecord model.PackageRecord, highWhenInstalled bool) (model.Severity, model.Confidence) {
	if packageRecordComesFromInstalledMetadata(packageRecord) {
		if highWhenInstalled {
			return model.SeverityHigh, model.ConfidenceProbable
		}

		return model.SeverityMedium, model.ConfidenceProbable
	}

	if highWhenInstalled {
		return model.SeverityMedium, model.ConfidencePossible
	}

	return model.SeverityLow, model.ConfidencePossible
}

func packageRecordComesFromInstalledMetadata(packageRecord model.PackageRecord) bool {
	switch packageRecord.Source {
	case "composer.lock", "vendor/composer/installed.json":
		return true
	default:
		return false
	}
}

func appHasSecureSessionCookieRuntimeOverride(app model.LaravelApp) bool {
	if !app.Environment.SessionSecureCookieDefined {
		return false
	}

	return boolFromEnvironmentValue(app.Environment.SessionSecureCookieValue)
}

func buildHeuristicFindingForPackageRecord(
	packageName string,
	app model.LaravelApp,
	packageRecord model.PackageRecord,
	severity model.Severity,
	confidence model.Confidence,
	title string,
	why string,
	remediation string,
) model.Finding {
	return model.Finding{
		ID:          buildFindingID(frameworkHeuristicsCheckID, "package."+strings.ReplaceAll(packageName, "/", "."), app.RootPath),
		CheckID:     frameworkHeuristicsCheckID,
		Class:       model.FindingClassHeuristic,
		Severity:    severity,
		Confidence:  confidence,
		Title:       title,
		Why:         why,
		Remediation: remediation,
		Evidence: []model.Evidence{
			{Label: "package", Detail: packageRecord.Name},
			{Label: "version", Detail: firstNonEmpty(packageRecord.Version, "unknown")},
			{Label: "source", Detail: packageRecord.Source},
			{Label: "inference", Detail: packageExposureInferenceDetail(packageRecord)},
		},
		Affected: []model.Target{
			appTarget(app),
		},
	}
}

func buildHeuristicFindingForPublicAdminToolArtifacts(app model.LaravelApp, artifacts []model.ArtifactRecord) model.Finding {
	evidence := []model.Evidence{}
	affected := []model.Target{appTarget(app)}

	for _, artifact := range artifacts {
		evidence = append(evidence, pathEvidence(artifact.Path)...)
		affected = append(affected, pathTarget(artifact.Path))
	}

	return model.Finding{
		ID:          buildFindingID(frameworkHeuristicsCheckID, "public_admin_tool", app.RootPath),
		CheckID:     frameworkHeuristicsCheckID,
		Class:       model.FindingClassHeuristic,
		Severity:    model.SeverityHigh,
		Confidence:  model.ConfidenceProbable,
		Title:       "Public web path contains admin or diagnostic tools",
		Why:         "Tools like Adminer, phpMyAdmin, or phpinfo make it much easier for attackers to inspect or control the server when they are left in a public web path.",
		Remediation: "Remove admin and diagnostic tools from public directories, or expose them only through tightly controlled temporary operator access.",
		Evidence:    evidence,
		Affected:    affected,
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}

	return ""
}

func packageExposureInferenceDetail(packageRecord model.PackageRecord) string {
	if packageRecordComesFromInstalledMetadata(packageRecord) {
		return "package appears installed in composer metadata and should be reviewed for production exposure"
	}

	return "package is declared in composer metadata but installation or runtime exposure was not confirmed from the available snapshot"
}
