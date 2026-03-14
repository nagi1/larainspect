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
			Title:             "Laravel Telescope package appears present",
			Why:               "Telescope can expose requests, queries, jobs, exceptions, and environment details if it is reachable or weakly gated in production.",
			Remediation:       "Verify Telescope is disabled or tightly gated in production and confirm the dashboard is not reachable without strong operator controls.",
			HighWhenInstalled: true,
		},
		{
			PackageName: "barryvdh/laravel-debugbar",
			Title:       "Laravel Debugbar package appears present",
			Why:         "Debugbar can expose SQL, timing, route, and exception details that help attackers understand the application internals.",
			Remediation: "Keep Debugbar out of production builds or prove it is disabled and unreachable in the deployed runtime.",
		},
		{
			PackageName: "itsgoingd/clockwork",
			Title:       "Clockwork package appears present",
			Why:         "Clockwork can expose request timelines, configuration clues, and debugging detail when it remains reachable on production hosts.",
			Remediation: "Verify Clockwork is not exposed in production and keep its routes or headers tightly restricted when used for diagnostics.",
		},
		{
			PackageName: "spatie/laravel-ignition",
			Title:       "Ignition package appears present",
			Why:         "Ignition and related error tooling can expose stack traces, config clues, and exception context when production hardening is incomplete.",
			Remediation: "Verify the production error handler does not expose Ignition debug surfaces and keep detailed exception tooling out of public reach.",
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
		Title:       "Public path contains diagnostic or admin tooling",
		Why:         "Adminer, phpMyAdmin, phpinfo, and similar tools materially expand an attack surface when they remain inside a served path.",
		Remediation: "Remove diagnostic and database-admin tools from the public tree or place them behind tightly controlled, temporary operational access.",
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
