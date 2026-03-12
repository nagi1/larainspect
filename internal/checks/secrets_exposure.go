package checks

import (
	"context"
	"encoding/base64"
	"strings"

	"github.com/nagi1/larainspect/internal/model"
)

const secretsExposureCheckID = "secrets.exposure"

type SecretsExposureCheck struct{}

func init() {
	MustRegister(SecretsExposureCheck{})
}

func (SecretsExposureCheck) ID() string {
	return secretsExposureCheckID
}

func (SecretsExposureCheck) Run(_ context.Context, _ model.ExecutionContext, snapshot model.Snapshot) (model.CheckResult, error) {
	findings := []model.Finding{}

	for _, app := range snapshot.Apps {
		if debugModeFinding, found := buildDebugModeFinding(app); found {
			findings = append(findings, debugModeFinding)
		}

		if missingAppKeyFinding, found := buildMissingAppKeyFinding(app); found {
			findings = append(findings, missingAppKeyFinding)
		}

		if invalidAppKeyFinding, found := buildInvalidAppKeyFinding(app); found {
			findings = append(findings, invalidAppKeyFinding)
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
		Title:       "APP_DEBUG is enabled in .env",
		Why:         "Verbose Laravel debug output can expose stack traces, internal paths, and sensitive configuration to attackers.",
		Remediation: "Disable APP_DEBUG for production deployments and verify the effective runtime config after clearing and rebuilding caches intentionally.",
		Evidence:    evidence,
		Affected: []model.Target{
			appTarget(app),
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
		Why:         "A missing application key often indicates an incomplete or broken deploy and can leave encryption-dependent features unusable or misconfigured.",
		Remediation: "Set APP_KEY through the intended deploy flow, then clear and rebuild Laravel caches so the runtime uses the updated value intentionally.",
		Evidence: []model.Evidence{
			{Label: "path", Detail: envPath.AbsolutePath},
			{Label: "env", Detail: "APP_KEY is not defined"},
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
		Title:       "APP_KEY does not match an expected Laravel format",
		Why:         "An invalid APP_KEY can break encryption-dependent features and often points to a malformed or incomplete production deploy.",
		Remediation: "Regenerate or restore APP_KEY through the intended deploy workflow and verify the effective runtime configuration after cache rebuilds.",
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
		Title:       "Cached Laravel config is world-readable",
		Why:         "Laravel's cached config can include secrets and effective runtime values that should not be readable by arbitrary local users.",
		Remediation: "Restrict bootstrap/cache/config.php to the deploy or runtime identities that need it and avoid world-readable config cache permissions.",
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
		Title:       "Public path contains environment backup files",
		Why:         "Environment backups inside a served path can expose credentials and app secrets directly to web clients.",
		Remediation: "Remove .env backups from served directories and keep secret material outside the web root with tightly scoped permissions.",
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
		Title:       "Public path contains sensitive artifacts",
		Why:         "SQL dumps, log files, archives, or VCS directories inside a served path can leak source, secrets, and operational history.",
		Remediation: "Remove sensitive artifacts from the public tree and keep backups, logs, and VCS metadata outside any served directory.",
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
		Title:       "Public upload-like path contains PHP files",
		Why:         "PHP files in upload or storage-adjacent public paths often become execution opportunities if the web boundary is too permissive.",
		Remediation: "Remove unexpected PHP files from upload-like paths and ensure Nginx or PHP-FPM never executes PHP from public storage or upload directories.",
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
