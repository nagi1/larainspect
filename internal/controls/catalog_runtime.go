package controls

func runtimeControls() []Control {
	return []Control{
		{
			ID:   "phpfpm.non-root-isolated-runtime",
			Name: "PHP-FPM runs as a non-root application runtime",
			Sources: []Source{
				source("php_manual", "OWASP PHP Configuration Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/PHP_Configuration_Cheat_Sheet.html"),
				source("laravel_docs", "Laravel Deployment Documentation", "https://laravel.com/docs/11.x/deployment"),
				source("owasp", "OWASP ASVS", "https://owasp.org/www-project-application-security-verification-standard/"),
			},
			Description:  "PHP-FPM pools should never run as root because that turns app compromise into host compromise too easily.",
			EvidenceType: EvidenceHostConfig,
			Status:       StatusImplemented,
			matches: []match{
				mapping("phpfpm.security", "phpfpm.security.root_pool"),
			},
		},
		{
			ID:   "phpfpm.runtime-environment-boundary",
			Name: "PHP-FPM pools inherit only the runtime environment they actually need",
			Sources: []Source{
				source("php_manual", "OWASP PHP Configuration Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/PHP_Configuration_Cheat_Sheet.html"),
				source("laravel_docs", "Laravel Deployment Documentation", "https://laravel.com/docs/11.x/deployment"),
				source("owasp", "OWASP ASVS", "https://owasp.org/www-project-application-security-verification-standard/"),
			},
			Description:  "PHP-FPM should avoid inheriting broad parent-service environment state and prefer explicit runtime variables for Laravel where possible.",
			EvidenceType: EvidenceHostConfig,
			Status:       StatusImplemented,
			matches: []match{
				mapping("phpfpm.security", "phpfpm.security.clear_env_disabled"),
			},
		},
		{
			ID:   "phpfpm.socket-and-listener-boundary",
			Name: "PHP-FPM listeners and sockets keep a narrow local trust boundary",
			Sources: []Source{
				source("php_manual", "OWASP PHP Configuration Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/PHP_Configuration_Cheat_Sheet.html"),
				source("linux_hardening", "Ubuntu Security Guide", "https://ubuntu.com/security/certifications/docs/usg"),
				source("owasp", "OWASP ASVS", "https://owasp.org/www-project-application-security-verification-standard/"),
			},
			Description:  "Prefer Unix sockets over TCP where practical and keep socket owner, group, and mode aligned to the intended Nginx access boundary only.",
			EvidenceType: EvidenceHostConfig,
			Status:       StatusImplemented,
			matches: []match{
				mapping("phpfpm.security", "phpfpm.security.broad_tcp_listener"),
				mapping("phpfpm.security", "phpfpm.security.loopback_tcp_listener"),
				mapping("phpfpm.security", "phpfpm.security.broad_socket_mode"),
				mapping("phpfpm.security", "phpfpm.security.missing_socket_acl"),
				mapping("phpfpm.security", "phpfpm.security.collapsed_socket_boundary"),
				mapping("phpfpm.security", "phpfpm.security.socket_acl_not_aligned"),
			},
		},
		{
			ID:   "phpfpm.per-app-isolation",
			Name: "Laravel apps keep separate PHP-FPM pools or runtime identities where practical",
			Sources: []Source{
				source("laravel_docs", "Laravel Deployment Documentation", "https://laravel.com/docs/11.x/deployment"),
				source("linux_hardening", "Ubuntu Security Guide", "https://ubuntu.com/security/certifications/docs/usg"),
				source("owasp", "OWASP ASVS", "https://owasp.org/www-project-application-security-verification-standard/"),
			},
			Description:  "Multiple apps should not silently share a PHP-FPM pool target or a reused runtime user unless the operator has intentionally accepted the isolation tradeoff.",
			EvidenceType: EvidenceHostConfig,
			Status:       StatusImplemented,
			matches: []match{
				mapping("phpfpm.security", "phpfpm.security.shared_pool"),
				mapping("phpfpm.security", "phpfpm.security.shared_runtime_user"),
			},
		},
	}
}
