package controls

func scopeBoundaryControls() []Control {
	return []Control{
		{
			ID:   "php.runtime-ini-benchmark-breadth",
			Name: "Generic php.ini benchmark coverage beyond Laravel-relevant evidence",
			Sources: []Source{
				source("php_manual", "OWASP PHP Configuration Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/PHP_Configuration_Cheat_Sheet.html"),
				source("php_manual", "PHP Security Introduction", "https://www.php.net/manual/en/security.intro.php"),
			},
			Description:      "A full php.ini benchmark could exist, but it would add broad runtime policy checking beyond the current Laravel-on-Linux product boundary.",
			EvidenceType:     EvidenceOutOfScope,
			Status:           StatusOutOfScope,
			OutOfScopeReason: "Keep larainspect focused on Laravel-adjacent controls with direct host or source evidence instead of becoming a generic PHP benchmark auditor.",
		},
		{
			ID:   "linux.full-host-benchmark-coverage",
			Name: "Full CIS, STIG, or generic Linux benchmark coverage",
			Sources: []Source{
				source("linux_hardening", "Ubuntu Security Guide", "https://ubuntu.com/security/certifications/docs/usg"),
				source("linux_hardening", "CIS Ubuntu Linux Benchmark", "https://www.cisecurity.org/benchmark/ubuntu_linux"),
			},
			Description:      "Generic host benchmark auditing covers far more than Laravel, Nginx, PHP-FPM, deploy workflows, or app-adjacent services.",
			EvidenceType:     EvidenceOutOfScope,
			Status:           StatusOutOfScope,
			OutOfScopeReason: "The project should not drift into a broad Linux benchmark scanner when the finding would not materially change Laravel application security decisions.",
		},
		{
			ID:   "linux.kernel-and-unrelated-benchmark-tuning",
			Name: "Kernel and unrelated host benchmark tuning",
			Sources: []Source{
				source("linux_hardening", "Ubuntu Security Guide", "https://ubuntu.com/security/certifications/docs/usg"),
				source("linux_hardening", "CIS Ubuntu Linux Benchmark", "https://www.cisecurity.org/benchmark/ubuntu_linux"),
			},
			Description:      "Kernel sysctls, unrelated daemon benchmarks, and package-level hardening outside the Laravel stack are intentionally excluded unless they directly affect app safety.",
			EvidenceType:     EvidenceOutOfScope,
			Status:           StatusOutOfScope,
			OutOfScopeReason: "These checks would broaden scope substantially while providing weak Laravel-specific signal in normal audits.",
		},
		{
			ID:   "infrastructure.remote-internet-dependent-auditing",
			Name: "Normal scans depend on remote internet lookups to evaluate host controls",
			Sources: []Source{
				source("owasp", "OWASP ASVS", "https://owasp.org/www-project-application-security-verification-standard/"),
				source("paragonie", "Paragonie Secure PHP Guide", "https://paragonie.com/blog/2017/12/2018-guide-building-secure-php-software"),
			},
			Description:      "Routine audits should remain predictable and local rather than requiring network retrieval of benchmarks or repository metadata.",
			EvidenceType:     EvidenceOutOfScope,
			Status:           StatusOutOfScope,
			OutOfScopeReason: "Internet-dependent control evaluation would weaken offline and host-safe operation and does not fit the current product boundary.",
		},
	}
}
