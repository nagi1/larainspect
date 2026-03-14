package checks_test

import (
	"context"
	"testing"

	"github.com/nagi1/larainspect/internal/checks"
	"github.com/nagi1/larainspect/internal/model"
)

func TestSourceConfigCheckReportsWardInspiredConfigSignals(t *testing.T) {
	t.Parallel()

	app := completeLaravelApp("/var/www/shop")
	app.SourceMatches = []model.SourceMatch{
		{RuleID: "laravel.config.app.debug_true", RelativePath: "config/app.php", Line: 12, Detail: "hardcodes debug mode to true in config/app.php"},
		{RuleID: "laravel.config.session.http_only_false", RelativePath: "config/session.php", Line: 22, Detail: "disables the HttpOnly flag for session cookies"},
		{RuleID: "laravel.config.cors.wildcard_origins", RelativePath: "config/cors.php", Line: 6, Detail: "allows wildcard CORS origins"},
		{RuleID: "laravel.config.cors.supports_credentials_true", RelativePath: "config/cors.php", Line: 7, Detail: "enables CORS credentials support"},
		{RuleID: "laravel.config.mail.hardcoded_password", RelativePath: "config/mail.php", Line: 18, Detail: "hardcodes a mail password in config/mail.php"},
		{RuleID: "laravel.config.logging.hardcoded_slack_webhook", RelativePath: "config/logging.php", Line: 14, Detail: "hardcodes a Slack webhook in config/logging.php"},
		{RuleID: "laravel.env.example.real_secret_value", RelativePath: ".env.example", Line: 3, Detail: "contains a credential-like example value for DB_PASSWORD"},
	}

	result, err := checks.SourceConfigCheck{}.Run(context.Background(), model.ExecutionContext{}, model.Snapshot{
		Apps: []model.LaravelApp{app},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if len(result.Findings) != 7 {
		t.Fatalf("expected 7 findings, got %+v", result.Findings)
	}

	for _, title := range []string{
		"Debug mode is hardcoded on in config/app.php",
		"Session cookies are readable by JavaScript",
		"CORS allows any website origin",
		"CORS allows credentials for any website origin",
		"Mail password is hardcoded in config/mail.php",
		"Slack webhook is hardcoded in config/logging.php",
		".env.example contains real-looking secret values",
	} {
		if !findingTitleExists(result.Findings, title) {
			t.Fatalf("expected finding title %q, got %+v", title, result.Findings)
		}
	}

	for _, finding := range result.Findings {
		switch finding.Title {
		case ".env.example contains real-looking secret values":
			if finding.Class != model.FindingClassHeuristic || finding.Confidence != model.ConfidencePossible {
				t.Fatalf("expected .env.example finding to stay heuristic/possible, got %+v", finding)
			}
		default:
			if finding.CheckID != "source.config" || (finding.Class != model.FindingClassDirect && finding.Title != ".env.example contains real-looking secret values") {
				t.Fatalf("unexpected finding metadata %+v", finding)
			}
		}
	}
}

func TestSourceConfigCheckSkipsAbsentSignals(t *testing.T) {
	t.Parallel()

	app := completeLaravelApp("/var/www/shop")

	result, err := checks.SourceConfigCheck{}.Run(context.Background(), model.ExecutionContext{}, model.Snapshot{
		Apps: []model.LaravelApp{app},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings, got %+v", result.Findings)
	}
}
