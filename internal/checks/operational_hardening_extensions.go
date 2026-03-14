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
				Title:       "Laravel runtime identity has SSH key-based access configured",
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
		return "The same identity appears to own deployment access, SSH login capability, and Laravel runtime duties, so a single credential can cross operator and runtime boundaries.",
			"Separate deploy SSH access from PHP-FPM and worker runtime identities so deployment credentials cannot directly become live application execution."
	}

	return "SSH key-based access for a Laravel runtime identity collapses the separation between operator access and the live application execution boundary.",
		"Keep SSH access on a distinct deploy or admin identity and run PHP-FPM, workers, and schedulers under a separate runtime account."
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
		Title:       "Operational principal can run sensitive sudo commands without a password",
		Why:         "Passwordless sudo for service-control, deploy, or filesystem mutation commands lowers the barrier between a compromised operational account and host-level changes around the Laravel boundary.",
		Remediation: "Keep NOPASSWD off sensitive operational commands where practical and require exact reviewed command allowlists for unavoidable elevation paths.",
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
		Title:       "Operational principal has broad sudo access",
		Why:         "Broad sudo for deploy or runtime-adjacent identities weakens separation between deploy, app runtime, and host administration duties.",
		Remediation: "Limit sudo to exact operational commands that are genuinely required and avoid granting ALL privileges to deploy or web-adjacent identities.",
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
		Title:       "Operational principal has wildcard sudo command allowance",
		Why:         "Wildcard sudo command patterns make it much easier for deploy or runtime-adjacent identities to expand a narrowly intended host action into broader privilege use.",
		Remediation: "Replace wildcard sudo command patterns with exact command allowlists for the few operational actions that are genuinely required.",
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
			Title:       "App-adjacent Laravel service does not declare explicit writable paths",
			Why:         "Laravel workers, schedulers, and similar app-adjacent services usually only need storage and bootstrap/cache writes, so leaving the writable boundary implicit makes permission drift harder to review.",
			Remediation: "Declare ReadWritePaths for the exact Laravel writable directories the service needs, typically storage and bootstrap/cache.",
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
		Title:       "App-adjacent systemd unit allows overly broad Laravel write paths",
		Why:         "Granting systemd write access to the wider Laravel tree weakens the intended boundary between immutable code and the small set of directories that should remain writable.",
		Remediation: "Reduce ReadWritePaths to the exact Laravel writable directories needed by the service instead of the app root or other broad code paths.",
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
