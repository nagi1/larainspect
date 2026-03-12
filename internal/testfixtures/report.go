package testfixtures

import (
	"time"

	"github.com/nagi/larainspect/internal/model"
)

func SampleReport() (model.Report, error) {
	findings := []model.Finding{
		{
			ID:          "filesystem.writable_env",
			CheckID:     "filesystem.writable_env",
			Class:       model.FindingClassDirect,
			Severity:    model.SeverityCritical,
			Confidence:  model.ConfidenceConfirmed,
			Title:       ".env is writable by the web runtime",
			Why:         "A writable .env lets the runtime or an attacker change secrets and application behavior.",
			Remediation: "Set .env ownership to the deploy user and remove runtime write access.",
			Evidence: []model.Evidence{
				{Label: "path", Detail: "/var/www/shop/.env"},
				{Label: "mode", Detail: "0664"},
			},
			Affected: []model.Target{
				{Type: "path", Path: "/var/www/shop/.env"},
			},
		},
		{
			ID:          "laravel.debug_mode",
			CheckID:     "laravel.debug_mode",
			Class:       model.FindingClassHeuristic,
			Severity:    model.SeverityMedium,
			Confidence:  model.ConfidencePossible,
			Title:       "APP_DEBUG appears to be enabled",
			Why:         "Verbose exception output can expose stack traces, paths, and secrets.",
			Remediation: "Verify production environment variables and cached config values.",
			Evidence: []model.Evidence{
				{Label: "env", Detail: "APP_DEBUG=true"},
			},
			Affected: []model.Target{
				{Type: "path", Path: "/var/www/shop/.env"},
			},
		},
		{
			ID:          "forensics.unexpected_php_file",
			CheckID:     "forensics.unexpected_php_file",
			Class:       model.FindingClassCompromiseIndicator,
			Severity:    model.SeverityHigh,
			Confidence:  model.ConfidenceProbable,
			Title:       "Unexpected PHP file in public uploads path",
			Why:         "Executable PHP in an upload path can indicate a dropped webshell or an unsafe execution boundary.",
			Remediation: "Remove executable handling from upload paths and investigate file provenance.",
			Evidence: []model.Evidence{
				{Label: "path", Detail: "/var/www/shop/public/uploads/cache.php"},
			},
			Affected: []model.Target{
				{Type: "path", Path: "/var/www/shop/public/uploads/cache.php"},
			},
		},
	}

	unknowns := []model.Unknown{
		{
			ID:      "nginx.main_config",
			CheckID: "nginx.main_config",
			Title:   "Could not inspect the main Nginx config",
			Reason:  "Permission denied while reading /etc/nginx/nginx.conf.",
			Error:   model.ErrorKindPermissionDenied,
			Affected: []model.Target{
				{Type: "path", Path: "/etc/nginx/nginx.conf"},
			},
		},
	}

	return model.BuildReport(
		model.Host{Hostname: "demo-vps", OS: "linux", Arch: "amd64"},
		time.Date(2024, time.May, 16, 12, 0, 0, 0, time.UTC),
		1250*time.Millisecond,
		findings,
		unknowns,
	)
}
