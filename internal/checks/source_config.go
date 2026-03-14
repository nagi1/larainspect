package checks

import (
	"context"

	"github.com/nagi1/larainspect/internal/model"
)

const sourceConfigCheckID = "source.config"

var _ Check = SourceConfigCheck{}

type SourceConfigCheck struct{}

func init() {
	MustRegister(SourceConfigCheck{})
}

func (SourceConfigCheck) ID() string {
	return sourceConfigCheckID
}

func (SourceConfigCheck) Description() string {
	return "Inspect deployed Laravel source configuration files for high-signal security misconfigurations."
}

func (SourceConfigCheck) Run(_ context.Context, _ model.ExecutionContext, snapshot model.Snapshot) (model.CheckResult, error) {
	findings := []model.Finding{}

	for _, app := range snapshot.Apps {
		if finding, found := buildRuleConfigFinding(snapshot, app,
			"debug_true",
			"laravel.config.app.debug_true",
			model.FindingClassDirect,
			model.SeverityHigh, model.ConfidenceProbable,
			"config/app.php hardcodes debug mode on",
			"Hardcoding Laravel debug mode on keeps verbose error output enabled regardless of environment settings and can expose stack traces, secrets, and internal paths.",
			"Read the debug flag from environment or runtime config and keep production debug output disabled.",
		); found {
			findings = append(findings, finding)
		}

		if finding, found := buildRuleConfigFinding(snapshot, app,
			"password_reset_expire_long",
			"laravel.config.auth.password_reset_expire_long",
			model.FindingClassDirect,
			model.SeverityLow, model.ConfidencePossible,
			"config/auth.php uses a long password reset expiry",
			"Long-lived password reset tokens widen the window for reuse when reset links are exposed, forwarded, or left in mailboxes.",
			"Reduce the password reset expiry to the shortest practical window for the application and review whether stale reset tokens are invalidated aggressively enough.",
		); found {
			findings = append(findings, finding)
		}

		if finding, found := buildRuleConfigFinding(snapshot, app,
			"http_only_false",
			"laravel.config.session.http_only_false",
			model.FindingClassDirect,
			model.SeverityHigh, model.ConfidenceProbable,
			"config/session.php disables HttpOnly session cookies",
			"Disabling the HttpOnly flag makes Laravel session cookies readable from JavaScript, which raises the impact of any XSS exposure materially.",
			"Enable HttpOnly for session cookies and confirm custom cookie code does not reintroduce script-readable session state elsewhere.",
		); found {
			findings = append(findings, finding)
		}

		if finding, found := buildRuleConfigFinding(snapshot, app,
			"same_site_none",
			"laravel.config.session.same_site_none",
			model.FindingClassDirect,
			model.SeverityMedium, model.ConfidenceProbable,
			"config/session.php permits cross-site session cookies",
			"Using SameSite none or null allows session cookies to accompany cross-site requests more broadly and weakens default CSRF containment.",
			"Prefer a SameSite value of lax or strict unless a specific cross-site session flow is required and separately protected.",
		); found {
			findings = append(findings, finding)
		}

		if finding, found := buildRuleConfigFinding(snapshot, app,
			"cors_wildcard_origins",
			"laravel.config.cors.wildcard_origins",
			model.FindingClassDirect,
			model.SeverityMedium, model.ConfidenceProbable,
			"config/cors.php allows wildcard origins",
			"Wildcard CORS origins let arbitrary sites read responses from browser-initiated requests when the rest of the policy permits it, which expands cross-origin data exposure risk.",
			"Replace wildcard origins with the exact frontend origins that should be allowed to call the application.",
		); found {
			findings = append(findings, finding)
		}

		corsWildcardMatches := sourceMatchesForRule(app, "laravel.config.cors.wildcard_origins")
		corsCredentialMatches := sourceMatchesForRule(app, "laravel.config.cors.supports_credentials_true")
		if len(corsWildcardMatches) > 0 && len(corsCredentialMatches) > 0 {
			findings = append(findings, buildSourceFinding(
				sourceConfigCheckID,
				"cors_credentials_with_wildcard",
				app,
				model.FindingClassDirect,
				model.SeverityHigh,
				model.ConfidenceProbable,
				"config/cors.php combines credentials with wildcard origins",
				"Credentialed cross-origin requests paired with wildcard origins are a brittle and dangerous policy combination that can expose authenticated application responses to untrusted sites.",
				"Do not allow credentials for wildcard origins. Restrict origins to the exact trusted frontends that need credentialed browser access.",
				append([]model.SourceMatch{}, corsWildcardMatches...),
				sourceMatchEvidenceForMatches(app, corsCredentialMatches),
			))
		}

		if finding, found := buildRuleConfigFinding(snapshot, app,
			"hardcoded_mail_password",
			"laravel.config.mail.hardcoded_password",
			model.FindingClassDirect,
			model.SeverityHigh, model.ConfidenceProbable,
			"config/mail.php hardcodes a mail credential",
			"Hardcoded mail credentials are easy to leak through source access, backups, or config cache artifacts and are harder to rotate safely than environment-managed secrets.",
			"Move mail credentials to the deploy-time secret source used for this environment and keep config files free of embedded passwords.",
		); found {
			findings = append(findings, finding)
		}

		if finding, found := buildRuleConfigFinding(snapshot, app,
			"hardcoded_database_password",
			"laravel.config.database.hardcoded_password",
			model.FindingClassDirect,
			model.SeverityHigh, model.ConfidenceProbable,
			"config/database.php hardcodes a database credential",
			"Embedding database credentials in Laravel config makes them available anywhere the source tree or cached config is exposed and complicates secret rotation.",
			"Keep database credentials in the environment or secret distribution mechanism used by the deployment, not in versioned config.",
		); found {
			findings = append(findings, finding)
		}

		if finding, found := buildRuleConfigFinding(snapshot, app,
			"hardcoded_broadcasting_secret",
			"laravel.config.broadcasting.hardcoded_secret",
			model.FindingClassDirect,
			model.SeverityMedium, model.ConfidenceProbable,
			"config/broadcasting.php hardcodes a service credential",
			"Hardcoded broadcasting secrets expand the blast radius of repository, backup, and config-cache exposure and are awkward to rotate under incident pressure.",
			"Read broadcasting keys and secrets from deployment-managed secrets instead of embedding them in config.",
		); found {
			findings = append(findings, finding)
		}

		if finding, found := buildRuleConfigFinding(snapshot, app,
			"hardcoded_slack_webhook",
			"laravel.config.logging.hardcoded_slack_webhook",
			model.FindingClassDirect,
			model.SeverityMedium, model.ConfidenceProbable,
			"config/logging.php hardcodes a Slack webhook",
			"Slack webhooks behave like bearer-style credentials. Embedding one in config makes it easier to leak and abuse for message spoofing or alert noise.",
			"Store Slack webhook URLs in the environment or secret manager used by the deployment and rotate any webhook that has been committed or deployed broadly.",
		); found {
			findings = append(findings, finding)
		}

		if finding, found := buildRuleConfigFinding(snapshot, app,
			"env_example_secret_value",
			"laravel.env.example.real_secret_value",
			model.FindingClassHeuristic,
			model.SeverityMedium, model.ConfidencePossible,
			".env.example contains credential-like values",
			"Credential-like values in .env.example are easy to commit, copy into real environments, or leak through build artifacts even when they were meant only as placeholders.",
			"Replace real-looking values in .env.example with unmistakable placeholders and rotate any secret that was copied from a tracked example file.",
		); found {
			findings = append(findings, finding)
		}
	}

	return model.CheckResult{Findings: findings}, nil
}

// buildRuleConfigFinding resolves metadata from the YAML rule definition
// (honoring config overrides) and falls back to the provided defaults.
func buildRuleConfigFinding(
	snapshot model.Snapshot,
	app model.LaravelApp,
	suffix string,
	ruleID string,
	class model.FindingClass,
	fallbackSeverity model.Severity,
	fallbackConfidence model.Confidence,
	fallbackTitle string,
	fallbackWhy string,
	fallbackRemediation string,
) (model.Finding, bool) {
	matches := sourceMatchesForRule(app, ruleID)
	if len(matches) == 0 {
		return model.Finding{}, false
	}

	severity, confidence, title, why, remediation := ruleMetadata(
		snapshot, ruleID,
		fallbackSeverity, fallbackConfidence, fallbackTitle, fallbackWhy, fallbackRemediation,
	)

	return buildSourceFinding(
		sourceConfigCheckID, suffix, app, class,
		severity, confidence, title, why, remediation,
		matches, nil,
	), true
}

func sourceMatchEvidenceForMatches(app model.LaravelApp, sourceMatches []model.SourceMatch) []model.Evidence {
	evidence := make([]model.Evidence, 0, len(sourceMatches)*2)
	for _, sourceMatch := range sourceMatches {
		evidence = append(evidence, sourceMatchEvidence(app, sourceMatch)...)
	}

	return evidence
}
