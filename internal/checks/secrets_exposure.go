package checks

import (
	"context"
	"encoding/base64"
	"strings"

	"github.com/nagi1/larainspect/internal/model"
)

const secretsExposureCheckID = "secrets.exposure"

var _ Check = SecretsExposureCheck{}

type SecretsExposureCheck struct{}

func init() {
	MustRegister(SecretsExposureCheck{})
}

func (SecretsExposureCheck) ID() string {
	return secretsExposureCheckID
}

func (SecretsExposureCheck) Description() string {
	return "Inspect Laravel secrets, backups, and sensitive file exposure risks."
}

func (SecretsExposureCheck) Run(_ context.Context, _ model.ExecutionContext, snapshot model.Snapshot) (model.CheckResult, error) {
	findings := []model.Finding{}

	for _, app := range snapshot.Apps {
		if debugModeFinding, found := buildDebugModeFinding(app); found {
			findings = append(findings, debugModeFinding)
		}

		if nonProductionAppEnvFinding, found := buildNonProductionAppEnvFinding(app); found {
			findings = append(findings, nonProductionAppEnvFinding)
		}

		if missingAppKeyFinding, found := buildMissingAppKeyFinding(app); found {
			findings = append(findings, missingAppKeyFinding)
		}

		if invalidAppKeyFinding, found := buildInvalidAppKeyFinding(app); found {
			findings = append(findings, invalidAppKeyFinding)
		}

		if emptyDatabasePasswordFinding, found := buildEmptyDatabasePasswordFinding(app); found {
			findings = append(findings, emptyDatabasePasswordFinding)
		}

		if worldReadableConfigCacheFinding, found := buildWorldReadableConfigCacheFinding(app); found {
			findings = append(findings, worldReadableConfigCacheFinding)
		}

		if publicEnvironmentBackupFinding, found := buildPublicEnvironmentBackupFinding(app); found {
			findings = append(findings, publicEnvironmentBackupFinding)
		}

		if publicSensitiveArtifactFinding, found := buildPublicSensitiveArtifactFinding(app); found {
			findings = append(findings, publicSensitiveArtifactFinding)
		}

		if publicUploadPHPFinding, found := buildPublicUploadPHPFinding(app); found {
			findings = append(findings, publicUploadPHPFinding)
		}
	}

	return model.CheckResult{Findings: findings}, nil
}

func buildDebugModeFinding(app model.LaravelApp) (model.Finding, bool) {
	if !app.Environment.AppDebugDefined || !boolFromEnvironmentValue(app.Environment.AppDebugValue) {
		return model.Finding{}, false
	}

	envPath, _ := app.PathRecord(".env")
	evidence := []model.Evidence{
		{Label: "env", Detail: "APP_DEBUG=" + app.Environment.AppDebugValue},
	}
	if envPath.AbsolutePath != "" {
		evidence = append(evidence, model.Evidence{Label: "path", Detail: envPath.AbsolutePath})
	}

	return model.Finding{
		ID:          buildFindingID(secretsExposureCheckID, "debug_enabled", app.RootPath),
		CheckID:     secretsExposureCheckID,
		Class:       model.FindingClassDirect,
		Severity:    model.SeverityMedium,
		Confidence:  model.ConfidenceProbable,
		Title:       "Debug mode is enabled in .env",
		Why:         "If debug mode is on in production, error pages may reveal stack traces, internal paths, and sensitive configuration.",
		Remediation: "Disable APP_DEBUG in production and verify the live runtime config after clearing and rebuilding caches.",
		Evidence:    evidence,
		Affected: []model.Target{
			appTarget(app),
		},
	}, true
}

func buildNonProductionAppEnvFinding(app model.LaravelApp) (model.Finding, bool) {
	if !app.Environment.AppEnvDefined {
		return model.Finding{}, false
	}

	switch strings.ToLower(strings.TrimSpace(app.Environment.AppEnvValue)) {
	case "local", "development", "dev":
	default:
		return model.Finding{}, false
	}

	envPath, found := app.PathRecord(".env")
	if !found || !envPath.Inspected || !envPath.Exists {
		return model.Finding{}, false
	}

	return model.Finding{
		ID:          buildFindingID(secretsExposureCheckID, "non_production_app_env", app.RootPath),
		CheckID:     secretsExposureCheckID,
		Class:       model.FindingClassDirect,
		Severity:    model.SeverityLow,
		Confidence:  model.ConfidenceProbable,
		Title:       "APP_ENV is set to a development value",
		Why:         "If a production server is still marked as local or development, it may keep weaker defaults or developer-only behavior enabled.",
		Remediation: "Set APP_ENV=production for production deployments and verify the live runtime configuration after rebuilding the config cache.",
		Evidence: []model.Evidence{
			{Label: "path", Detail: envPath.AbsolutePath},
			{Label: "env", Detail: "APP_ENV=" + app.Environment.AppEnvValue},
		},
		Affected: []model.Target{
			pathTarget(envPath),
		},
	}, true
}

func buildMissingAppKeyFinding(app model.LaravelApp) (model.Finding, bool) {
	envPath, found := app.PathRecord(".env")
	if !found || !envPath.Inspected || !envPath.Exists || app.Environment.AppKeyDefined {
		return model.Finding{}, false
	}

	return model.Finding{
		ID:          buildFindingID(secretsExposureCheckID, "missing_app_key", app.RootPath),
		CheckID:     secretsExposureCheckID,
		Class:       model.FindingClassDirect,
		Severity:    model.SeverityMedium,
		Confidence:  model.ConfidenceProbable,
		Title:       "APP_KEY is missing from .env",
		Why:         "If APP_KEY is missing, encrypted Laravel features may break and the deploy may be incomplete.",
		Remediation: "Set APP_KEY through the normal deploy flow, then clear and rebuild Laravel caches so the app picks up the new value.",
		Evidence: []model.Evidence{
			{Label: "path", Detail: envPath.AbsolutePath},
			{Label: "env", Detail: "APP_KEY is not defined"},
		},
		Affected: []model.Target{
			pathTarget(envPath),
		},
	}, true
}

func buildEmptyDatabasePasswordFinding(app model.LaravelApp) (model.Finding, bool) {
	envPath, found := app.PathRecord(".env")
	if !found || !envPath.Inspected || !envPath.Exists || !app.Environment.DBPasswordDefined || !app.Environment.DBPasswordEmpty {
		return model.Finding{}, false
	}

	return model.Finding{
		ID:          buildFindingID(secretsExposureCheckID, "empty_db_password", app.RootPath),
		CheckID:     secretsExposureCheckID,
		Class:       model.FindingClassDirect,
		Severity:    model.SeverityLow,
		Confidence:  model.ConfidenceProbable,
		Title:       "Database password is empty in .env",
		Why:         "On a deployed server, an empty database password often points to weak or incomplete database authentication.",
		Remediation: "Set a non-empty database password for deployed environments, or document the host-level authentication setup that makes an empty password safe.",
		Evidence: []model.Evidence{
			{Label: "path", Detail: envPath.AbsolutePath},
			{Label: "env", Detail: "DB_PASSWORD is empty"},
		},
		Affected: []model.Target{
			pathTarget(envPath),
		},
	}, true
}

func buildInvalidAppKeyFinding(app model.LaravelApp) (model.Finding, bool) {
	envPath, found := app.PathRecord(".env")
	if !found || !envPath.Inspected || !envPath.Exists || !app.Environment.AppKeyDefined || appKeyLooksValid(app.Environment.AppKeyValue) {
		return model.Finding{}, false
	}

	return model.Finding{
		ID:          buildFindingID(secretsExposureCheckID, "invalid_app_key", app.RootPath),
		CheckID:     secretsExposureCheckID,
		Class:       model.FindingClassDirect,
		Severity:    model.SeverityMedium,
		Confidence:  model.ConfidenceProbable,
		Title:       "APP_KEY does not look valid for Laravel",
		Why:         "If APP_KEY is malformed, encrypted Laravel features may fail and the deploy may be incomplete or broken.",
		Remediation: "Regenerate or restore APP_KEY through the normal deploy workflow and verify the live runtime configuration after rebuilding caches.",
		Evidence: []model.Evidence{
			{Label: "path", Detail: envPath.AbsolutePath},
			{Label: "env", Detail: "APP_KEY is present but does not look valid"},
		},
		Affected: []model.Target{
			pathTarget(envPath),
		},
	}, true
}

func buildWorldReadableConfigCacheFinding(app model.LaravelApp) (model.Finding, bool) {
	configCachePath, found := app.PathRecord("bootstrap/cache/config.php")
	if !found || !configCachePath.Inspected || !configCachePath.Exists || !configCachePath.IsWorldReadable() {
		return model.Finding{}, false
	}

	return model.Finding{
		ID:          buildFindingID(secretsExposureCheckID, "world_readable_config_cache", configCachePath.AbsolutePath),
		CheckID:     secretsExposureCheckID,
		Class:       model.FindingClassDirect,
		Severity:    model.SeverityHigh,
		Confidence:  model.ConfidenceConfirmed,
		Title:       "Cached config file can be read by any local user",
		Why:         "Laravel's cached config may contain secrets and effective runtime values that local users should not be able to read.",
		Remediation: "Limit bootstrap/cache/config.php to the deploy or runtime users that need it, and avoid world-readable permissions.",
		Evidence:    pathEvidence(configCachePath),
		Affected: []model.Target{
			pathTarget(configCachePath),
		},
	}, true
}

func buildPublicEnvironmentBackupFinding(app model.LaravelApp) (model.Finding, bool) {
	publicEnvironmentBackups := []model.ArtifactRecord{}

	for _, artifact := range app.Artifacts {
		if artifact.Kind == model.ArtifactKindEnvironmentBackup && artifact.WithinPublicPath {
			publicEnvironmentBackups = append(publicEnvironmentBackups, artifact)
		}
	}

	if len(publicEnvironmentBackups) == 0 {
		return model.Finding{}, false
	}

	evidence := []model.Evidence{}
	affected := []model.Target{appTarget(app)}
	for _, artifact := range publicEnvironmentBackups {
		evidence = append(evidence, pathEvidence(artifact.Path)...)
		affected = append(affected, pathTarget(artifact.Path))
	}

	return model.Finding{
		ID:          buildFindingID(secretsExposureCheckID, "public_environment_backup", app.RootPath),
		CheckID:     secretsExposureCheckID,
		Class:       model.FindingClassDirect,
		Severity:    model.SeverityCritical,
		Confidence:  model.ConfidenceConfirmed,
		Title:       "Public web path contains .env backup files",
		Why:         "If .env backups sit inside a served path, database credentials and app secrets may be downloadable over the web.",
		Remediation: "Remove .env backups from served directories and keep secret material outside the web root with tight permissions.",
		Evidence:    evidence,
		Affected:    affected,
	}, true
}

func buildPublicSensitiveArtifactFinding(app model.LaravelApp) (model.Finding, bool) {
	publicSensitiveArtifacts := []model.ArtifactRecord{}

	for _, artifact := range app.Artifacts {
		switch artifact.Kind {
		case model.ArtifactKindPublicSensitiveFile, model.ArtifactKindVersionControlPath:
			if artifact.WithinPublicPath {
				publicSensitiveArtifacts = append(publicSensitiveArtifacts, artifact)
			}
		}
	}

	if len(publicSensitiveArtifacts) == 0 {
		return model.Finding{}, false
	}

	evidence := []model.Evidence{}
	affected := []model.Target{appTarget(app)}
	for _, artifact := range publicSensitiveArtifacts {
		evidence = append(evidence, pathEvidence(artifact.Path)...)
		affected = append(affected, pathTarget(artifact.Path))
	}

	return model.Finding{
		ID:          buildFindingID(secretsExposureCheckID, "public_sensitive_artifact", app.RootPath),
		CheckID:     secretsExposureCheckID,
		Class:       model.FindingClassDirect,
		Severity:    model.SeverityHigh,
		Confidence:  model.ConfidenceConfirmed,
		Title:       "Public web path contains sensitive files",
		Why:         "SQL dumps, log files, archives, or Git metadata in a served path can leak source, secrets, and operational history.",
		Remediation: "Remove sensitive files from the public tree and keep backups, logs, and version-control metadata outside any served directory.",
		Evidence:    evidence,
		Affected:    affected,
	}, true
}

func buildPublicUploadPHPFinding(app model.LaravelApp) (model.Finding, bool) {
	publicPHPArtifacts := []model.ArtifactRecord{}

	for _, artifact := range app.Artifacts {
		if artifact.Kind == model.ArtifactKindPublicPHPFile && artifact.WithinPublicPath && artifact.UploadLikePath {
			publicPHPArtifacts = append(publicPHPArtifacts, artifact)
		}
	}

	if len(publicPHPArtifacts) == 0 {
		return model.Finding{}, false
	}

	evidence := []model.Evidence{}
	affected := []model.Target{appTarget(app)}
	for _, artifact := range publicPHPArtifacts {
		evidence = append(evidence, pathEvidence(artifact.Path)...)
		affected = append(affected, pathTarget(artifact.Path))
	}

	return model.Finding{
		ID:          buildFindingID(secretsExposureCheckID, "public_upload_php", app.RootPath),
		CheckID:     secretsExposureCheckID,
		Class:       model.FindingClassDirect,
		Severity:    model.SeverityHigh,
		Confidence:  model.ConfidenceProbable,
		Title:       "Public upload directory contains PHP files",
		Why:         "If PHP files appear in upload or storage-related public paths, they may become executable if the web server is too permissive.",
		Remediation: "Remove unexpected PHP files from upload paths and make sure Nginx or PHP-FPM never executes PHP from public storage or upload directories.",
		Evidence:    evidence,
		Affected:    affected,
	}, true
}

func appKeyLooksValid(value string) bool {
	trimmedValue := strings.TrimSpace(value)
	if trimmedValue == "" {
		return false
	}

	if strings.HasPrefix(trimmedValue, "base64:") {
		encodedValue := strings.TrimPrefix(trimmedValue, "base64:")
		if encodedValue == "" {
			return false
		}

		decodedValue, err := base64.StdEncoding.DecodeString(encodedValue)
		return err == nil && len(decodedValue) >= 16
	}

	return len(trimmedValue) >= 16
}
