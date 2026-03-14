package checks

import (
	"strconv"
	"strings"

	"github.com/nagi1/larainspect/internal/model"
)

func collectRuntimeSSHAccessFindings(snapshot model.Snapshot, sshAccountsByUser map[string]model.SSHAccount) []model.Finding {
	findings := []model.Finding{}

	for _, app := range snapshot.Apps {
		runtimeIdentities := collectAppRuntimeIdentities(app, snapshot)
		deployUsers := appDeployUsers(app, snapshot)

		for _, runtimeUser := range runtimeIdentities.Users {
			account, found := sshAccountsByUser[runtimeUser]
			if !found {
				continue
			}

			why, remediation := runtimeSSHBoundaryNarrative(deployUsers, runtimeUser)
			evidence := runtimeSSHAccessEvidence(app, snapshot, runtimeUser, account)

			findings = append(findings, model.Finding{
				ID:          buildFindingID(operationalHardeningCheckID, "runtime_ssh_access", app.RootPath+"."+runtimeUser),
				CheckID:     operationalHardeningCheckID,
				Class:       model.FindingClassHeuristic,
				Severity:    model.SeverityHigh,
				Confidence:  model.ConfidenceProbable,
				Title:       "Laravel runtime user can log in over SSH",
				Why:         why,
				Remediation: remediation,
				Evidence:    evidence,
				Affected: []model.Target{
					appTarget(app),
					{Type: "path", Path: account.AuthorizedKeys.AbsolutePath},
				},
			})
		}
	}

	return findings
}

func runtimeSSHBoundaryNarrative(deployUsers []string, runtimeUser string) (string, string) {
	if containsString(deployUsers, runtimeUser) {
		return "The same account appears to handle deployment, SSH access, and app runtime work. If that one credential is compromised, an attacker can move directly from app access to server administration.",
			"Use separate accounts for SSH administration and deploy work versus PHP-FPM and worker runtime. The runtime user should not have an interactive SSH key."
	}

	return "Giving the Laravel runtime user SSH access removes the separation between day-to-day server access and the account that executes the app.",
		"Keep SSH access on a distinct deploy or admin account and run PHP-FPM, workers, and schedulers under a separate runtime account."
}

func runtimeSSHAccessEvidence(app model.LaravelApp, snapshot model.Snapshot, runtimeUser string, account model.SSHAccount) []model.Evidence {
	evidence := []model.Evidence{
		{Label: "app", Detail: app.RootPath},
		{Label: "runtime_user", Detail: runtimeUser},
		{Label: "authorized_keys", Detail: account.AuthorizedKeys.AbsolutePath},
	}

	return append(evidence, appRuntimeSourceEvidence(app, snapshot, runtimeUser)...)
}

func buildOperationalSudoFinding(rule model.SudoRule, sshAccountsByUser map[string]model.SSHAccount) (model.Finding, bool) {
	evidence := operationalSudoEvidence(rule, sshAccountsByUser)

	if rule.AllCommands {
		return newBroadSudoFinding(rule, evidence), true
	}
	if sudoRuleHasWildcardCommands(rule) {
		return newWildcardSudoFinding(rule, evidence), true
	}
	if !rule.NoPassword || !sudoRuleHasSensitiveOperationalCommands(rule) {
		return model.Finding{}, false
	}

	return model.Finding{
		ID:          buildFindingID(operationalHardeningCheckID, "nopasswd_sensitive_sudo", rule.Path+"."+rule.Principal),
		CheckID:     operationalHardeningCheckID,
		Class:       model.FindingClassHeuristic,
		Severity:    model.SeverityHigh,
		Confidence:  model.ConfidenceProbable,
		Title:       "Operational user can run sensitive sudo commands without a password",
		Why:         "Passwordless sudo for service control, deploy, or file-changing commands makes it much easier for a compromised operational account to change the host immediately.",
		Remediation: "Avoid NOPASSWD for sensitive commands where practical, and keep any remaining sudo access on a short, reviewed allowlist of exact commands.",
		Evidence:    evidence,
		Affected:    []model.Target{{Type: "path", Path: rule.Path}},
	}, true
}

func operationalSudoEvidence(rule model.SudoRule, sshAccountsByUser map[string]model.SSHAccount) []model.Evidence {
	evidence := []model.Evidence{
		{Label: "path", Detail: rule.Path},
		{Label: "principal", Detail: rule.Principal},
		{Label: "command_count", Detail: strconv.Itoa(len(rule.Commands))},
	}

	if rule.RunAs != "" {
		evidence = append(evidence, model.Evidence{Label: "run_as", Detail: rule.RunAs})
	}
	if rule.NoPassword {
		evidence = append(evidence, model.Evidence{Label: "auth", Detail: "NOPASSWD"})
	}
	for _, command := range selectSudoEvidenceCommands(rule.Commands) {
		evidence = append(evidence, model.Evidence{Label: "command", Detail: command})
	}
	if account, found := sshAccountsByUser[strings.TrimSpace(strings.TrimPrefix(rule.Principal, "%"))]; found {
		evidence = append(evidence, model.Evidence{Label: "authorized_keys", Detail: account.AuthorizedKeys.AbsolutePath})
	}

	return evidence
}

func newBroadSudoFinding(rule model.SudoRule, evidence []model.Evidence) model.Finding {
	return model.Finding{
		ID:          buildFindingID(operationalHardeningCheckID, "broad_sudo", rule.Path+"."+rule.Principal),
		CheckID:     operationalHardeningCheckID,
		Class:       model.FindingClassDirect,
		Severity:    sudoRuleSeverity(rule),
		Confidence:  model.ConfidenceConfirmed,
		Title:       "Operational user has unrestricted sudo access",
		Why:         "This account can become root for essentially anything. If the account is misused or compromised, the separation between deploy work, app runtime, and full server administration disappears.",
		Remediation: "Replace broad sudo access with a short allowlist of the exact commands this user truly needs. Do not grant ALL to deploy or web-adjacent accounts.",
		Evidence:    evidence,
		Affected:    []model.Target{{Type: "path", Path: rule.Path}},
	}
}

func newWildcardSudoFinding(rule model.SudoRule, evidence []model.Evidence) model.Finding {
	return model.Finding{
		ID:          buildFindingID(operationalHardeningCheckID, "wildcard_sudo", rule.Path+"."+rule.Principal),
		CheckID:     operationalHardeningCheckID,
		Class:       model.FindingClassDirect,
		Severity:    sudoRuleSeverity(rule),
		Confidence:  model.ConfidenceConfirmed,
		Title:       "Operational user has wildcard sudo rules",
		Why:         "Wildcard sudo rules make it easy for a user to run more commands than intended, especially as file names, service names, or arguments change over time.",
		Remediation: "Replace wildcard patterns with explicit command paths and fixed arguments for the few elevated actions this user actually needs.",
		Evidence:    evidence,
		Affected:    []model.Target{{Type: "path", Path: rule.Path}},
	}
}

func sudoRuleSeverity(rule model.SudoRule) model.Severity {
	if rule.NoPassword {
		return model.SeverityCritical
	}

	return model.SeverityHigh
}

func sudoRuleHasWildcardCommands(rule model.SudoRule) bool {
	for _, command := range rule.Commands {
		if strings.ContainsAny(strings.TrimSpace(command), "*?") {
			return true
		}
	}

	return false
}

func sudoRuleHasSensitiveOperationalCommands(rule model.SudoRule) bool {
	for _, command := range rule.Commands {
		if sudoCommandLooksSensitive(command) {
			return true
		}
	}

	return false
}

func sudoCommandLooksSensitive(command string) bool {
	normalizedCommand := strings.ToLower(strings.TrimSpace(command))

	switch {
	case strings.Contains(normalizedCommand, "systemctl"),
		strings.Contains(normalizedCommand, "service "),
		strings.Contains(normalizedCommand, "supervisorctl"),
		strings.Contains(normalizedCommand, "sudoedit"),
		strings.Contains(normalizedCommand, "/bin/sh"),
		strings.Contains(normalizedCommand, "/bin/bash"),
		strings.Contains(normalizedCommand, " chmod "),
		strings.Contains(normalizedCommand, " chown "),
		strings.Contains(normalizedCommand, " rsync "),
		strings.Contains(normalizedCommand, " rm "),
		commandLooksLikeComposer(normalizedCommand),
		commandLooksLikeDirectArtisanTask(normalizedCommand),
		commandLooksLikeArtisanMaintenance(normalizedCommand):
		return true
	default:
		return false
	}
}

func buildLaravelWritableBoundaryFinding(unit model.SystemdUnit, app model.LaravelApp, broadPaths []string) model.Finding {
	evidence := []model.Evidence{
		{Label: "unit", Detail: unit.Name},
		{Label: "path", Detail: unit.Path},
		{Label: "app", Detail: app.RootPath},
		{Label: "exec_start", Detail: unit.ExecStart},
	}

	if len(broadPaths) == 0 {
		return model.Finding{
			ID:          buildFindingID(operationalHardeningCheckID, "laravel_writable_boundary", unit.Path+"."+app.RootPath),
			CheckID:     operationalHardeningCheckID,
			Class:       model.FindingClassHeuristic,
			Severity:    model.SeverityMedium,
			Confidence:  model.ConfidenceProbable,
			Title:       "Systemd service does not list which Laravel paths it may write",
			Why:         "Laravel workers and schedulers usually need to write only to storage/ and bootstrap/cache/. If write access is left implicit, drift is harder to review.",
			Remediation: "Declare ReadWritePaths for the exact Laravel directories the service needs to write, usually storage/ and bootstrap/cache/.",
			Evidence:    evidence,
			Affected: []model.Target{
				{Type: "path", Path: unit.Path},
				appTarget(app),
			},
		}
	}

	for _, broadPath := range broadPaths {
		evidence = append(evidence, model.Evidence{Label: "read_write_path", Detail: broadPath})
	}

	return model.Finding{
		ID:          buildFindingID(operationalHardeningCheckID, "laravel_writable_boundary", unit.Path+"."+app.RootPath),
		CheckID:     operationalHardeningCheckID,
		Class:       model.FindingClassHeuristic,
		Severity:    model.SeverityHigh,
		Confidence:  model.ConfidenceConfirmed,
		Title:       "Systemd service can write more of the Laravel app than it should",
		Why:         "If the service can write to broad parts of the app tree, code and configuration are easier to change by mistake or after a compromise.",
		Remediation: "Reduce ReadWritePaths to the exact Laravel directories the service needs instead of allowing the app root or other broad code paths.",
		Evidence:    evidence,
		Affected: []model.Target{
			{Type: "path", Path: unit.Path},
			appTarget(app),
		},
	}
}

func appRuntimeSourceEvidence(app model.LaravelApp, snapshot model.Snapshot, user string) []model.Evidence {
	evidence := []model.Evidence{}

	for _, pool := range matchedPHPFPMPoolsForApp(app, snapshot.NginxSites, snapshot.PHPFPMPools) {
		if strings.TrimSpace(pool.User) != user {
			continue
		}

		evidence = append(evidence, model.Evidence{Label: "php_fpm_pool", Detail: pool.ConfigPath + ":" + pool.Name})
	}

	for _, record := range operationalRecordsForApp(app, snapshot, commandLooksLikeRuntimeWorkflow) {
		if strings.TrimSpace(record.RuntimeUser) != user {
			continue
		}

		evidence = append(evidence, model.Evidence{Label: record.SourceType, Detail: record.SourcePath})
	}

	return evidence
}

func commandLooksLikeRuntimeWorkflow(command string) bool {
	return commandLooksLikeQueueWorker(command) ||
		commandLooksLikeHorizon(command) ||
		commandLooksLikeScheduler(command)
}
