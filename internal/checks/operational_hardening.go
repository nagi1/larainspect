package checks

import (
	"context"
	"strings"

	"github.com/nagi1/larainspect/internal/model"
)

const operationalHardeningCheckID = "operations.hardening"

var _ Check = OperationalHardeningCheck{}

type OperationalHardeningCheck struct{}

func init() {
	MustRegister(OperationalHardeningCheck{})
}

func (OperationalHardeningCheck) ID() string {
	return operationalHardeningCheckID
}

func (OperationalHardeningCheck) Description() string {
	return "Inspect host and service hardening controls around the Laravel stack."
}

func (OperationalHardeningCheck) Run(_ context.Context, _ model.ExecutionContext, snapshot model.Snapshot) (model.CheckResult, error) {
	findings := []model.Finding{}
	operationalPrincipals := collectOperationalPrincipals(snapshot)
	sshAccountsByUser := authorizedSSHAccountsByUser(snapshot.SSHAccounts)

	for _, sshConfig := range snapshot.SSHConfigs {
		if strings.EqualFold(strings.TrimSpace(sshConfig.PermitRootLogin), "yes") {
			findings = append(findings, model.Finding{
				ID:          buildFindingID(operationalHardeningCheckID, "root_ssh_login", sshConfig.Path),
				CheckID:     operationalHardeningCheckID,
				Class:       model.FindingClassDirect,
				Severity:    model.SeverityHigh,
				Confidence:  model.ConfidenceConfirmed,
				Title:       "SSH allows direct root login",
				Why:         "Direct root SSH login increases the chance that credential theft or key misuse immediately becomes full host compromise.",
				Remediation: "Disable direct root SSH login where practical and use a dedicated deploy or admin user with narrowly reviewed escalation instead.",
				Evidence: []model.Evidence{
					{Label: "config", Detail: sshConfig.Path},
					{Label: "permit_root_login", Detail: sshConfig.PermitRootLogin},
				},
				Affected: []model.Target{{Type: "path", Path: sshConfig.Path}},
			})
		}

		if strings.EqualFold(strings.TrimSpace(sshConfig.PasswordAuthentication), "yes") {
			findings = append(findings, model.Finding{
				ID:          buildFindingID(operationalHardeningCheckID, "ssh_password_auth", sshConfig.Path),
				CheckID:     operationalHardeningCheckID,
				Class:       model.FindingClassHeuristic,
				Severity:    model.SeverityMedium,
				Confidence:  model.ConfidenceProbable,
				Title:       "SSH password authentication appears enabled",
				Why:         "Password-based SSH access increases brute-force and credential-reuse risk on hosts that should prefer key-based administration.",
				Remediation: "Prefer key-based SSH authentication for Laravel VPS administration and disable password authentication where the access model allows it.",
				Evidence: []model.Evidence{
					{Label: "config", Detail: sshConfig.Path},
					{Label: "password_authentication", Detail: sshConfig.PasswordAuthentication},
				},
				Affected: []model.Target{{Type: "path", Path: sshConfig.Path}},
			})
		}
	}

	findings = append(findings, collectSSHAccountPermissionFindings(snapshot.SSHAccounts)...)
	findings = append(findings, collectRuntimeSSHAccessFindings(snapshot, sshAccountsByUser)...)

	for _, rule := range snapshot.SudoRules {
		if !sudoRuleTargetsOperationalPrincipal(rule, operationalPrincipals) {
			continue
		}

		if finding, found := buildOperationalSudoFinding(rule, sshAccountsByUser); found {
			findings = append(findings, finding)
		}
	}

	for _, unit := range snapshot.SystemdUnits {
		if !systemdUnitLooksAppAdjacent(unit) {
			continue
		}

		if unit.NoNewPrivileges == "" || !strings.EqualFold(strings.TrimSpace(unit.NoNewPrivileges), "yes") {
			findings = append(findings, buildSystemdHardeningFinding(unit, "missing_no_new_privileges", "App-adjacent systemd unit does not enable NoNewPrivileges", "Without NoNewPrivileges, service compromise can retain more privilege-escalation opportunities than necessary.", "Set NoNewPrivileges=yes on app-adjacent units where practical."))
		}

		if unit.ProtectSystem == "" {
			findings = append(findings, buildSystemdHardeningFinding(unit, "missing_protect_system", "App-adjacent systemd unit does not set ProtectSystem", "Without ProtectSystem or an equivalent filesystem restriction, app-adjacent services have a broader writable host surface than necessary.", "Set ProtectSystem=strict or another justified restrictive mode and make explicit writable exceptions with ReadWritePaths."))
		}

		if len(unit.ReadWritePaths) == 0 && strings.Contains(strings.ToLower(unit.ExecStart), "php-fpm") {
			findings = append(findings, buildSystemdHardeningFinding(unit, "missing_read_write_paths", "PHP-FPM service does not declare explicit writable paths", "Explicit writable-path declarations help keep the PHP service boundary narrow and make drift easier to detect.", "Constrain PHP-FPM writable paths with ReadWritePaths or equivalent service hardening where practical."))
		}

		for _, matchedApp := range matchedSystemdApps(unit, snapshot.Apps) {
			if systemdUnitNeedsLaravelWritablePaths(unit) && len(unit.ReadWritePaths) == 0 {
				findings = append(findings, buildLaravelWritableBoundaryFinding(unit, matchedApp, nil))
			}

			if broadPaths := systemdUnitBroadWritablePaths(unit, matchedApp); len(broadPaths) > 0 {
				findings = append(findings, buildLaravelWritableBoundaryFinding(unit, matchedApp, broadPaths))
			}
		}
	}

	if firewallAppearsDisabled(snapshot.FirewallSummaries) && hasBroadOperationalListener(snapshot.Listeners) {
		findings = append(findings, model.Finding{
			ID:          buildFindingID(operationalHardeningCheckID, "firewall_disabled", "host"),
			CheckID:     operationalHardeningCheckID,
			Class:       model.FindingClassHeuristic,
			Severity:    model.SeverityMedium,
			Confidence:  model.ConfidenceProbable,
			Title:       "Firewall summaries appear disabled while broad listeners are present",
			Why:         "Broad service listeners without an active host firewall increase the chance that internal-only services are reachable more widely than intended.",
			Remediation: "Review the host firewall policy and ensure broad listeners are intentionally exposed rather than relying on default network reachability.",
			Evidence:    firewallEvidence(snapshot.FirewallSummaries, snapshot.Listeners),
			Affected:    []model.Target{{Type: "name", Name: "host"}},
		})
	}

	for _, app := range snapshot.Apps {
		if logsPath, found := app.PathRecord("storage/logs"); found && logsPath.IsWorldReadable() {
			findings = append(findings, model.Finding{
				ID:          buildFindingID(operationalHardeningCheckID, "world_readable_logs", logsPath.AbsolutePath),
				CheckID:     operationalHardeningCheckID,
				Class:       model.FindingClassDirect,
				Severity:    model.SeverityMedium,
				Confidence:  model.ConfidenceConfirmed,
				Title:       "Laravel log directory is world-readable",
				Why:         "World-readable logs can expose stack traces, secrets, queue payload details, and operational metadata to unintended local users.",
				Remediation: "Restrict storage/logs to the deploy and runtime identities that need it and keep logs outside any served path.",
				Evidence:    pathEvidence(logsPath),
				Affected: []model.Target{
					appTarget(app),
					pathTarget(logsPath),
				},
			})
		}
	}

	return model.CheckResult{Findings: findings}, nil
}

type sshPathPolicy struct {
	record          func(model.SSHAccount) []model.PathRecord
	expectedMaxMode uint32
	suffix          string
	title           string
	why             string
	remediation     string
}

func collectSSHAccountPermissionFindings(accounts []model.SSHAccount) []model.Finding {
	policies := []sshPathPolicy{
		{
			record:          func(account model.SSHAccount) []model.PathRecord { return []model.PathRecord{account.SSHDir} },
			expectedMaxMode: 0o700,
			suffix:          "ssh_dir_permissions",
			title:           "SSH directory permissions are broader than 0700",
			why:             "An SSH home directory with group or world access makes key material and account trust boundaries easier to tamper with or inspect unexpectedly.",
			remediation:     "Restrict ~/.ssh to mode 0700 or stricter for every operational account.",
		},
		{
			record:          func(account model.SSHAccount) []model.PathRecord { return []model.PathRecord{account.AuthorizedKeys} },
			expectedMaxMode: 0o600,
			suffix:          "authorized_keys_permissions",
			title:           "authorized_keys permissions are broader than 0600",
			why:             "A broadly readable or writable authorized_keys file weakens trust over who can add, replace, or inspect SSH access grants for the account.",
			remediation:     "Restrict authorized_keys to mode 0600 or stricter and keep ownership aligned with the intended account.",
		},
		{
			record:          func(account model.SSHAccount) []model.PathRecord { return account.PrivateKeys },
			expectedMaxMode: 0o600,
			suffix:          "private_key_permissions",
			title:           "SSH private key permissions are broader than 0600",
			why:             "Broadly readable or writable private key files materially increase the chance that operational SSH credentials are copied, replaced, or abused.",
			remediation:     "Restrict private key files to mode 0600 or stricter and rotate any key that has been broadly exposed.",
		},
	}

	findings := []model.Finding{}
	for _, account := range accounts {
		for _, policy := range policies {
			for _, pathRecord := range policy.record(account) {
				finding, found := buildSSHAccountPathFinding(account.User, pathRecord, policy)
				if !found {
					continue
				}
				findings = append(findings, finding)
			}
		}
	}

	return findings
}

func buildSystemdHardeningFinding(unit model.SystemdUnit, suffix string, title string, why string, remediation string) model.Finding {
	evidence := []model.Evidence{
		{Label: "unit", Detail: unit.Name},
		{Label: "path", Detail: unit.Path},
		{Label: "exec_start", Detail: unit.ExecStart},
	}
	if unit.WorkingDirectory != "" {
		evidence = append(evidence, model.Evidence{Label: "working_directory", Detail: unit.WorkingDirectory})
	}

	return model.Finding{
		ID:          buildFindingID(operationalHardeningCheckID, suffix, unit.Path),
		CheckID:     operationalHardeningCheckID,
		Class:       model.FindingClassHeuristic,
		Severity:    model.SeverityMedium,
		Confidence:  model.ConfidenceProbable,
		Title:       title,
		Why:         why,
		Remediation: remediation,
		Evidence:    evidence,
		Affected: []model.Target{
			{Type: "path", Path: unit.Path},
		},
	}
}

func hasBroadOperationalListener(listeners []model.ListenerRecord) bool {
	for _, listener := range listeners {
		if isBroadListenerAddress(listener.LocalAddress) && !isLoopbackListenerAddress(listener.LocalAddress) {
			return true
		}
	}

	return false
}

func firewallEvidence(summaries []model.FirewallSummary, listeners []model.ListenerRecord) []model.Evidence {
	evidence := make([]model.Evidence, 0, len(summaries)+len(listeners))
	for _, summary := range summaries {
		state := summary.State
		if state == "" {
			state = "unknown"
		}
		evidence = append(evidence, model.Evidence{Label: summary.Source, Detail: state})
	}

	for _, listener := range listeners {
		if !isBroadListenerAddress(listener.LocalAddress) || isLoopbackListenerAddress(listener.LocalAddress) {
			continue
		}

		evidence = append(evidence, model.Evidence{Label: "listener", Detail: listener.LocalAddress + ":" + listener.LocalPort})
	}

	return evidence
}

func buildSSHAccountPathFinding(user string, pathRecord model.PathRecord, policy sshPathPolicy) (model.Finding, bool) {
	if !pathRecord.Inspected || !pathRecord.Exists || !pathModeExceeds(pathRecord, policy.expectedMaxMode) {
		return model.Finding{}, false
	}

	evidence := append(pathEvidence(pathRecord),
		model.Evidence{Label: "account", Detail: user},
		model.Evidence{Label: "expected_max_mode", Detail: expectedModeOctal(policy.expectedMaxMode)},
	)

	return model.Finding{
		ID:          buildFindingID(operationalHardeningCheckID, policy.suffix, pathRecord.AbsolutePath),
		CheckID:     operationalHardeningCheckID,
		Class:       model.FindingClassDirect,
		Severity:    model.SeverityHigh,
		Confidence:  model.ConfidenceConfirmed,
		Title:       policy.title,
		Why:         policy.why,
		Remediation: policy.remediation,
		Evidence:    evidence,
		Affected: []model.Target{
			{Type: "path", Path: pathRecord.AbsolutePath},
		},
	}, true
}
