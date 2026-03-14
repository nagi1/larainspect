package controls

func applicationControls() []Control {
	return []Control{
		{
			ID:   "laravel.project-owner-runtime-split",
			Name: "Laravel project ownership stays separate from the runtime identity",
			Sources: []Source{
				source("laravel_docs", "Laravel Deployment Documentation", "https://laravel.com/docs/11.x/deployment"),
				source("platform_docs", "Laravel Forge Deployment Documentation", "https://forge.laravel.com/docs/sites/deployments"),
				source("owasp", "OWASP Laravel Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Laravel_Cheat_Sheet.html"),
			},
			Description:  "Keep the deployed app tree owned by deploy or admin identities and prevent the web or worker runtime from owning code or sensitive configuration.",
			EvidenceType: EvidenceHostPath,
			Status:       StatusImplemented,
			matches: []match{
				mapping("filesystem.permissions", "filesystem.permissions.runtime_owned_project_root"),
				mapping("filesystem.permissions", "filesystem.permissions.runtime_writable_sensitive_paths"),
			},
		},
		{
			ID:   "laravel.permission-shape-baseline",
			Name: "Laravel code and config keep a hardened permission shape",
			Sources: []Source{
				source("laravel_docs", "Laravel Deployment Documentation", "https://laravel.com/docs/11.x/deployment"),
				source("owasp", "OWASP Laravel Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Laravel_Cheat_Sheet.html"),
				source("linux_hardening", "Ubuntu Security Guide", "https://ubuntu.com/security/certifications/docs/usg"),
			},
			Description:  "Normal application paths should avoid world write access and broad mode drift, with only the intended writable Laravel paths left writable.",
			EvidenceType: EvidenceHostPath,
			Status:       StatusImplemented,
			matches: []match{
				mapping("filesystem.permissions", "filesystem.permissions.world_writable_paths"),
				mapping("filesystem.permissions", "filesystem.permissions.over_permissive_normal_paths"),
				mapping("filesystem.permissions", "filesystem.permissions.writable_path_baseline"),
			},
		},
		{
			ID:   "laravel.env-integrity-and-permissions",
			Name: "Laravel environment files stay private, non-runtime-owned, and within the intended deployment boundary",
			Sources: []Source{
				source("laravel_docs", "Laravel Configuration Documentation", "https://laravel.com/docs/11.x/configuration"),
				source("owasp", "OWASP Laravel Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Laravel_Cheat_Sheet.html"),
				source("php_manual", "PHP Security Introduction", "https://www.php.net/manual/en/security.intro.php"),
			},
			Description:  "The .env file should not be world-readable, runtime-owned, or redirected through an unexpected symlink outside the app's trusted deployment layout.",
			EvidenceType: EvidenceHostPath,
			Status:       StatusImplemented,
			matches: []match{
				mapping("filesystem.permissions", "filesystem.permissions.world_readable_env"),
				mapping("filesystem.permissions", "filesystem.permissions.symlinked_env"),
				mapping("filesystem.permissions", "filesystem.permissions.runtime_owned_env"),
			},
		},
		{
			ID:   "laravel.public-docroot-boundary",
			Name: "Only Laravel public/ is served by Nginx",
			Sources: []Source{
				source("laravel_docs", "Laravel Deployment Documentation", "https://laravel.com/docs/11.x/deployment"),
				source("platform_docs", "Laravel Forge Deployment Documentation", "https://forge.laravel.com/docs/sites/deployments"),
				source("owasp", "OWASP ASVS", "https://owasp.org/www-project-application-security-verification-standard/"),
			},
			Description:  "Nginx must point at the Laravel public directory rather than the project root so private code, config, and backups never become directly web-accessible.",
			EvidenceType: EvidenceHostConfig,
			Status:       StatusImplemented,
			matches: []match{
				mapping("nginx.boundaries", "nginx.boundaries.project_root_served"),
			},
		},
		{
			ID:   "laravel.sensitive-public-deny-rules",
			Name: "Hidden files, environment artifacts, and backup leftovers are explicitly denied by Nginx",
			Sources: []Source{
				source("laravel_docs", "Laravel Deployment Documentation", "https://laravel.com/docs/11.x/deployment"),
				source("php_manual", "PHP Security Introduction", "https://www.php.net/manual/en/security.intro.php"),
				source("owasp", "OWASP ASVS", "https://owasp.org/www-project-application-security-verification-standard/"),
			},
			Description:  "Nginx should deny direct access to dotfiles, .env variants, VCS metadata, and common backup or dump artifacts.",
			EvidenceType: EvidenceHostConfig,
			Status:       StatusImplemented,
			matches: []match{
				mapping("nginx.boundaries", "nginx.boundaries.missing_deny_rules"),
			},
		},
		{
			ID:   "laravel.public-symlink-storage-boundary",
			Name: "Public symlinks expose only the intended Laravel storage target",
			Sources: []Source{
				source("owasp", "OWASP Laravel Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Laravel_Cheat_Sheet.html"),
				source("owasp", "OWASP File Upload Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html"),
				source("laravel_docs", "Laravel Deployment Documentation", "https://laravel.com/docs/11.x/deployment"),
			},
			Description:  "public/storage and any other public-facing symlink should resolve only to intentional storage targets, not to private app paths or unrelated shared content.",
			EvidenceType: EvidenceHostPath,
			Status:       StatusImplemented,
			matches: []match{
				mapping("nginx.boundaries", "nginx.boundaries.unexpected_public_storage_symlink"),
				mapping("nginx.boundaries", "nginx.boundaries.private_public_symlink"),
			},
		},
		{
			ID:   "uploads.no-public-php-execution",
			Name: "Upload and storage-adjacent public paths never execute PHP",
			Sources: []Source{
				source("php_manual", "PHP File Upload Handling", "https://www.php.net/manual/en/features.file-upload.php"),
				source("owasp", "OWASP File Upload Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html"),
				source("owasp", "OWASP Laravel Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Laravel_Cheat_Sheet.html"),
			},
			Description:  "Public upload and storage-adjacent directories should never inherit generic PHP execution rules through Nginx or PHP-FPM routing.",
			EvidenceType: EvidenceHostConfig,
			Status:       StatusImplemented,
			matches: []match{
				mapping("nginx.boundaries", "nginx.boundaries.generic_php_execution"),
				mapping("nginx.boundaries", "nginx.boundaries.upload_execution"),
			},
		},
		{
			ID:   "uploads.safe-file-type-allowlist",
			Name: "Uploads are restricted to explicitly safe file types with clear validation limits",
			Sources: []Source{
				source("php_manual", "PHP File Upload Handling", "https://www.php.net/manual/en/features.file-upload.php"),
				source("owasp", "OWASP File Upload Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html"),
				source("owasp", "OWASP ASVS", "https://owasp.org/www-project-application-security-verification-standard/"),
			},
			Description:  "Upload validation should deny executable file types and avoid bare file rules that omit obvious type or size restrictions.",
			EvidenceType: EvidenceSourceCode,
			Status:       StatusPartial,
			MissingWork:  "Correlate source-side upload rules with host-side exposure so private import flows are not treated the same as public user uploads.",
			matches: []match{
				mapping("source.security", "source.security.upload_executable_mimes"),
				mapping("source.security", "source.security.upload_file_without_constraints"),
			},
		},
		{
			ID:   "uploads.active-content-controls",
			Name: "SVG and HTML uploads receive explicit active-content handling",
			Sources: []Source{
				source("owasp", "OWASP File Upload Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html"),
				source("php_manual", "PHP File Upload Handling", "https://www.php.net/manual/en/features.file-upload.php"),
				source("owasp", "OWASP ASVS", "https://owasp.org/www-project-application-security-verification-standard/"),
			},
			Description:  "Risky active-content uploads such as SVG and HTML should be sanitized, scoped, or served only through safe download-oriented flows.",
			EvidenceType: EvidenceHybrid,
			Status:       StatusPartial,
			MissingWork:  "Add discovery for public delivery posture, content-disposition behavior, and sanitization signals before raising stronger host-backed findings.",
			matches: []match{
				mapping("source.security", "source.security.upload_risky_web_types"),
			},
		},
		{
			ID:   "php.runtime-debug-and-diagnostic-exposure",
			Name: "Production Laravel and PHP deployments avoid debug and diagnostic exposure",
			Sources: []Source{
				source("laravel_docs", "Laravel Configuration Documentation", "https://laravel.com/docs/11.x/configuration"),
				source("owasp", "OWASP Laravel Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Laravel_Cheat_Sheet.html"),
				source("php_manual", "PHP Security Introduction", "https://www.php.net/manual/en/security.intro.php"),
			},
			Description:  "Production code and config should not hardcode debug mode, ship phpinfo endpoints, or keep dump-style diagnostics in reachable paths.",
			EvidenceType: EvidenceSourceCode,
			Status:       StatusPartial,
			MissingWork:  "Add stronger host-side evidence for debug page reachability and production environment correlation instead of relying only on source signals.",
			matches: []match{
				mapping("source.config", "source.config.debug_true"),
				mapping("source.security", "source.security.phpinfo_call"),
				mapping("source.security", "source.security.dd_call"),
				mapping("source.security", "source.security.dump_calls"),
			},
		},
		{
			ID:   "php.session-cookie-policy",
			Name: "Laravel session cookies keep protective browser flags",
			Sources: []Source{
				source("php_manual", "PHP Sessions And Security", "https://www.php.net/manual/en/session.security.php"),
				source("php_manual", "PHP Session Security Management", "https://www.php.net/manual/en/features.session.security.management.php"),
				source("owasp", "OWASP ASVS", "https://owasp.org/www-project-application-security-verification-standard/"),
			},
			Description:  "Session cookies should keep HttpOnly enabled and avoid cross-site settings broader than the application genuinely requires.",
			EvidenceType: EvidenceSourceCode,
			Status:       StatusPartial,
			MissingWork:  "Add host or runtime-aware evidence for effective cookie flags after config caching and environment substitution.",
			matches: []match{
				mapping("source.config", "source.config.http_only_false"),
				mapping("source.config", "source.config.same_site_none"),
			},
		},
		{
			ID:   "laravel.secrets-out-of-versioned-config",
			Name: "Secrets stay out of committed Laravel config and example files",
			Sources: []Source{
				source("laravel_docs", "Laravel Configuration Documentation", "https://laravel.com/docs/11.x/configuration"),
				source("owasp", "OWASP Laravel Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Laravel_Cheat_Sheet.html"),
				source("paragonie", "Paragonie Secure PHP Guide", "https://paragonie.com/blog/2017/12/2018-guide-building-secure-php-software"),
			},
			Description:  "Passwords, webhooks, and other credentials should live in deployment-managed secret sources, not in committed config or realistic example files.",
			EvidenceType: EvidenceSourceCode,
			Status:       StatusImplemented,
			matches: []match{
				mapping("source.config", "source.config.hardcoded_mail_password"),
				mapping("source.config", "source.config.hardcoded_database_password"),
				mapping("source.config", "source.config.hardcoded_broadcasting_secret"),
				mapping("source.config", "source.config.hardcoded_slack_webhook"),
				mapping("source.config", "source.config.env_example_secret_value"),
			},
		},
		{
			ID:   "laravel.cors-origin-and-credentials-boundary",
			Name: "CORS policies do not combine wildcard trust with credentialed access",
			Sources: []Source{
				source("owasp", "OWASP ASVS", "https://owasp.org/www-project-application-security-verification-standard/"),
				source("owasp", "OWASP Laravel Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Laravel_Cheat_Sheet.html"),
				source("laravel_docs", "Laravel Configuration Documentation", "https://laravel.com/docs/11.x/configuration"),
			},
			Description:  "Cross-origin policies should allow only explicit frontend origins and must not pair wildcard origins with credentialed browser access.",
			EvidenceType: EvidenceSourceCode,
			Status:       StatusImplemented,
			matches: []match{
				mapping("source.config", "source.config.cors_wildcard_origins"),
				mapping("source.config", "source.config.cors_credentials_with_wildcard"),
			},
		},
	}
}
