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
			"Debug mode is hardcoded on in config/app.php",
			"If debug mode is forced on in code, the app may keep showing detailed errors even when production environment settings say otherwise.",
			"Read the debug setting from the environment and make sure production keeps detailed error pages disabled.",
		); found {
			findings = append(findings, finding)
		}

		if finding, found := buildRuleConfigFinding(snapshot, app,
			"password_reset_expire_long",
			"laravel.config.auth.password_reset_expire_long",
			model.FindingClassDirect,
			model.SeverityLow, model.ConfidencePossible,
			"Password reset links stay valid for too long",
			"The longer a reset link stays valid, the more time someone has to reuse it if the message is forwarded, leaked, or left in a mailbox.",
			"Shorten the password reset expiry to the smallest practical window and make sure old reset links are invalidated promptly.",
		); found {
			findings = append(findings, finding)
		}

		if finding, found := buildRuleConfigFinding(snapshot, app,
			"http_only_false",
			"laravel.config.session.http_only_false",
			model.FindingClassDirect,
			model.SeverityHigh, model.ConfidenceProbable,
			"Session cookies are readable by JavaScript",
			"If HttpOnly is disabled, any XSS bug can read the session cookie directly in the browser.",
			"Enable HttpOnly on session cookies and make sure custom cookie code does not reintroduce script-readable session state.",
		); found {
			findings = append(findings, finding)
		}

		if finding, found := buildRuleConfigFinding(snapshot, app,
			"same_site_none",
			"laravel.config.session.same_site_none",
			model.FindingClassDirect,
			model.SeverityMedium, model.ConfidenceProbable,
			"Session cookies are allowed on cross-site requests",
			"Allowing SameSite none or null makes it easier for the browser to send session cookies with cross-site requests.",
			"Use SameSite=lax or strict unless a specific cross-site flow is required and separately protected.",
		); found {
			findings = append(findings, finding)
		}

		if finding, found := buildRuleConfigFinding(snapshot, app,
			"cors_wildcard_origins",
			"laravel.config.cors.wildcard_origins",
			model.FindingClassDirect,
			model.SeverityMedium, model.ConfidenceProbable,
			"CORS allows any website origin",
			"If CORS allows every origin, other websites may be able to read app responses from a user's browser when the rest of the policy permits it.",
			"Replace wildcard origins with the exact frontend domains that should be allowed to call the app.",
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
				"CORS allows credentials for any website origin",
				"Allowing credentials with wildcard origins can let untrusted sites read authenticated responses from a user's browser.",
				"Do not allow credentials for wildcard origins. Limit this policy to the exact trusted frontend domains that need signed-in browser access.",
				append([]model.SourceMatch{}, corsWildcardMatches...),
				sourceMatchEvidenceForMatches(app, corsCredentialMatches),
			))
		}

		if finding, found := buildRuleConfigFinding(snapshot, app,
			"hardcoded_mail_password",
			"laravel.config.mail.hardcoded_password",
			model.FindingClassDirect,
			model.SeverityHigh, model.ConfidenceProbable,
			"Mail password is hardcoded in config/mail.php",
			"A password stored directly in code is easier to leak through source access, backups, or cached config files.",
			"Move mail credentials into the environment or secret store used during deployment and remove passwords from config files.",
		); found {
			findings = append(findings, finding)
		}

		if finding, found := buildRuleConfigFinding(snapshot, app,
			"hardcoded_database_password",
			"laravel.config.database.hardcoded_password",
			model.FindingClassDirect,
			model.SeverityHigh, model.ConfidenceProbable,
			"Database password is hardcoded in config/database.php",
			"A database password stored in code is easier to leak anywhere the source tree or cached config becomes visible.",
			"Keep database credentials in the environment or secret store used by deployment, not in versioned config files.",
		); found {
			findings = append(findings, finding)
		}

		if finding, found := buildRuleConfigFinding(snapshot, app,
			"hardcoded_broadcasting_secret",
			"laravel.config.broadcasting.hardcoded_secret",
			model.FindingClassDirect,
			model.SeverityMedium, model.ConfidenceProbable,
			"Broadcasting secret is hardcoded in config/broadcasting.php",
			"A service secret stored in code is easier to leak through the repository, backups, or cached config files.",
			"Read broadcasting keys and secrets from deployment-managed secrets instead of embedding them in config.",
		); found {
			findings = append(findings, finding)
		}

		if finding, found := buildRuleConfigFinding(snapshot, app,
			"hardcoded_slack_webhook",
			"laravel.config.logging.hardcoded_slack_webhook",
			model.FindingClassDirect,
			model.SeverityMedium, model.ConfidenceProbable,
			"Slack webhook is hardcoded in config/logging.php",
			"A Slack webhook URL acts like a secret. If it is stored in code, it is easier to leak and abuse for fake or noisy alerts.",
			"Store Slack webhook URLs in the environment or secret manager used by deployment, and rotate any webhook that has already been committed or widely deployed.",
		); found {
			findings = append(findings, finding)
		}

		if finding, found := buildRuleConfigFinding(snapshot, app,
			"env_example_secret_value",
			"laravel.env.example.real_secret_value",
			model.FindingClassHeuristic,
			model.SeverityMedium, model.ConfidencePossible,
			".env.example contains real-looking secret values",
			"Values that look real in .env.example are easy to copy into production by mistake or leak through commits and build artifacts.",
			"Replace them with obvious placeholders and rotate any secret that was copied from a tracked example file.",
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
