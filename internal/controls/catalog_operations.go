package controls

func operationsControls() []Control {
	return []Control{
		{
			ID:   "deploy.least-privilege-workflows",
			Name: "Deploy, Composer, and maintenance workflows run with least privilege",
			Sources: []Source{
				source("laravel_docs", "Laravel Deployment Documentation", "https://laravel.com/docs/11.x/deployment"),
				source("platform_docs", "Laravel Forge Deployment Documentation", "https://forge.laravel.com/docs/sites/deployments"),
				source("owasp", "OWASP ASVS", "https://owasp.org/www-project-application-security-verification-standard/"),
			},
			Description:  "Composer, restore, cache-build, and maintenance commands should run as deploy or app identities instead of root and should avoid blanket recursive permission resets.",
			EvidenceType: EvidenceHostConfig,
			Status:       StatusImplemented,
			matches: []match{
				mapping("operations.deploy", "operations.deploy.root_composer"),
				mapping("operations.deploy", "operations.deploy.dangerous_permission_reset"),
				mapping("operations.deploy", "operations.deploy.root_restore_or_maintenance"),
				mapping("operations.cron", "operations.cron.root_maintenance"),
			},
		},
		{
			ID:   "deploy.immutable-release-and-current-switch",
			Name: "Deployments prefer immutable releases over mutating one live tree",
			Sources: []Source{
				source("laravel_docs", "Laravel Deployment Documentation", "https://laravel.com/docs/11.x/deployment"),
				source("platform_docs", "Laravel Forge Deployment Documentation", "https://forge.laravel.com/docs/sites/deployments"),
			},
			Description:  "Release-based layouts make rollback, ownership checks, and writable-path boundaries more reliable than mutating one live directory in place.",
			EvidenceType: EvidenceHostPath,
			Status:       StatusImplemented,
			matches: []match{
				mapping("operations.deploy", "operations.deploy.mutable_live_tree"),
				mapping("operations.deploy", "operations.deploy.writable_previous_release"),
				mapping("operations.deploy", "operations.deploy.version_control_path"),
			},
		},
		{
			ID:   "deploy.post-deploy-drift-verification",
			Name: "Post-deploy verification keeps Laravel ownership and writable boundaries intact",
			Sources: []Source{
				source("laravel_docs", "Laravel Deployment Documentation", "https://laravel.com/docs/11.x/deployment"),
				source("platform_docs", "Laravel Forge Deployment Documentation", "https://forge.laravel.com/docs/sites/deployments"),
				source("owasp", "OWASP ASVS", "https://owasp.org/www-project-application-security-verification-standard/"),
			},
			Description:  "After each deploy, operators should verify that code, .env, symlinks, writable paths, and previous releases still match the intended Laravel deployment model.",
			EvidenceType: EvidenceHybrid,
			Status:       StatusImplemented,
			matches: []match{
				mapping("operations.deploy", "operations.deploy.post_deploy_drift"),
			},
		},
		{
			ID:   "operations.worker-scheduler-identity-and-release-consistency",
			Name: "Workers and schedulers stay on the intended identity and current release",
			Sources: []Source{
				source("laravel_docs", "Laravel Deployment Documentation", "https://laravel.com/docs/11.x/deployment"),
				source("platform_docs", "Laravel Forge Deployment Documentation", "https://forge.laravel.com/docs/sites/deployments"),
				source("owasp", "OWASP Laravel Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Laravel_Cheat_Sheet.html"),
			},
			Description:  "Queue workers and schedulers should not run as root, should not duplicate schedules, and should track the current release path after deploys.",
			EvidenceType: EvidenceHostConfig,
			Status:       StatusImplemented,
			matches: []match{
				mapping("operations.workers", "operations.workers.root_worker"),
				mapping("operations.workers", "operations.workers.root_scheduler"),
				mapping("operations.workers", "operations.workers.duplicate_scheduler"),
				mapping("operations.workers", "operations.workers.stale_release_reference"),
			},
		},
		{
			ID:   "operations.ssh-access-hygiene",
			Name: "Operational SSH access uses hardened key and login settings",
			Sources: []Source{
				source("linux_hardening", "Ubuntu Security Guide", "https://ubuntu.com/security/certifications/docs/usg"),
				source("linux_hardening", "CIS Ubuntu Linux Benchmark", "https://www.cisecurity.org/benchmark/ubuntu_linux"),
			},
			Description:  "Direct root login, password authentication, and weak SSH file permissions should be avoided for deploy and admin accounts.",
			EvidenceType: EvidenceHostConfig,
			Status:       StatusImplemented,
			matches: []match{
				mapping("operations.hardening", "operations.hardening.root_ssh_login"),
				mapping("operations.hardening", "operations.hardening.ssh_password_auth"),
				mapping("operations.hardening", "operations.hardening.ssh_dir_permissions"),
				mapping("operations.hardening", "operations.hardening.authorized_keys_permissions"),
				mapping("operations.hardening", "operations.hardening.private_key_permissions"),
				mapping("operations.hardening", "operations.hardening.runtime_ssh_access"),
			},
		},
		{
			ID:   "operations.sudo-minimization",
			Name: "Deploy and runtime-adjacent users avoid broad sudo grants",
			Sources: []Source{
				source("linux_hardening", "Ubuntu Security Guide", "https://ubuntu.com/security/certifications/docs/usg"),
				source("linux_hardening", "CIS Ubuntu Linux Benchmark", "https://www.cisecurity.org/benchmark/ubuntu_linux"),
				source("owasp", "OWASP ASVS", "https://owasp.org/www-project-application-security-verification-standard/"),
			},
			Description:  "Deploy or runtime-adjacent principals should not keep broad sudo privileges, especially not passwordless ALL access.",
			EvidenceType: EvidenceHostConfig,
			Status:       StatusImplemented,
			matches: []match{
				mapping("operations.hardening", "operations.hardening.broad_sudo"),
				mapping("operations.hardening", "operations.hardening.wildcard_sudo"),
				mapping("operations.hardening", "operations.hardening.nopasswd_sensitive_sudo"),
			},
		},
		{
			ID:   "services.systemd-writable-path-confinement",
			Name: "App-adjacent services declare hardening and writable-path boundaries",
			Sources: []Source{
				source("linux_hardening", "Ubuntu Security Guide", "https://ubuntu.com/security/certifications/docs/usg"),
				source("linux_hardening", "CIS Ubuntu Linux Benchmark", "https://www.cisecurity.org/benchmark/ubuntu_linux"),
			},
			Description:  "App-adjacent systemd units benefit from NoNewPrivileges, ProtectSystem, and explicit writable-path declarations to keep service-level blast radius narrow.",
			EvidenceType: EvidenceHostConfig,
			Status:       StatusImplemented,
			matches: []match{
				mapping("operations.hardening", "operations.hardening.missing_no_new_privileges"),
				mapping("operations.hardening", "operations.hardening.missing_protect_system"),
				mapping("operations.hardening", "operations.hardening.missing_read_write_paths"),
				mapping("operations.hardening", "operations.hardening.laravel_writable_boundary"),
			},
		},
		{
			ID:   "services.internal-listener-exposure",
			Name: "Internal services keep narrow listener exposure",
			Sources: []Source{
				source("linux_hardening", "Ubuntu Security Guide", "https://ubuntu.com/security/certifications/docs/usg"),
				source("linux_hardening", "CIS Ubuntu Linux Benchmark", "https://www.cisecurity.org/benchmark/ubuntu_linux"),
				source("owasp", "OWASP ASVS", "https://owasp.org/www-project-application-security-verification-standard/"),
			},
			Description:  "MySQL, Postgres, Redis, PHP-FPM, and Supervisor control surfaces should not bind broadly without an intentional, well-contained exposure model.",
			EvidenceType: EvidenceHostConfig,
			Status:       StatusImplemented,
			matches: []match{
				mapping("operations.network", "operations.network.broad_listener"),
				mapping("operations.network", "operations.network.supervisor_http_exposed"),
				mapping("operations.hardening", "operations.hardening.firewall_disabled"),
			},
		},
		{
			ID:   "logs.sensitive-runtime-log-access",
			Name: "Laravel runtime logs stay private to intended operators and runtimes",
			Sources: []Source{
				source("owasp", "OWASP Laravel Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Laravel_Cheat_Sheet.html"),
				source("paragonie", "Paragonie Secure PHP Guide", "https://paragonie.com/blog/2017/12/2018-guide-building-secure-php-software"),
				source("linux_hardening", "Ubuntu Security Guide", "https://ubuntu.com/security/certifications/docs/usg"),
			},
			Description:  "Application logs should not be world-readable because they often hold stack traces, secrets, or request details.",
			EvidenceType: EvidenceHostPath,
			Status:       StatusImplemented,
			matches: []match{
				mapping("operations.hardening", "operations.hardening.world_readable_logs"),
			},
		},
		{
			ID:   "recovery.backup-and-restore-permission-integrity",
			Name: "Backup and restore workflows preserve Laravel ownership and writable-path boundaries",
			Sources: []Source{
				source("laravel_docs", "Laravel Deployment Documentation", "https://laravel.com/docs/11.x/deployment"),
				source("platform_docs", "Laravel Forge Deployment Documentation", "https://forge.laravel.com/docs/sites/deployments"),
				source("owasp", "OWASP ASVS", "https://owasp.org/www-project-application-security-verification-standard/"),
			},
			Description:  "Restore workflows should not create root-owned or runtime-owned drift, leak backup artifacts publicly, or weaken the intended release and writable-path model.",
			EvidenceType: EvidenceHybrid,
			Status:       StatusImplemented,
			matches: []match{
				mapping("operations.deploy", "operations.deploy.root_restore_or_maintenance"),
				mapping("operations.deploy", "operations.deploy.post_restore_drift"),
				mapping("operations.cron", "operations.cron.public_backup_artifact"),
				mapping("operations.cron", "operations.cron.public_output"),
			},
		},
	}
}
