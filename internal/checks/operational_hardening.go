package checks

import (
	"context"
	"strings"

	"github.com/nagi1/larainspect/internal/model"
)

const operationalHardeningCheckID = "operations.hardening"

type OperationalHardeningCheck struct{}

func init() {
	MustRegister(OperationalHardeningCheck{})
}

func (OperationalHardeningCheck) ID() string {
	return operationalHardeningCheckID
}

func (OperationalHardeningCheck) Run(_ context.Context, _ model.ExecutionContext, snapshot model.Snapshot) (model.CheckResult, error) {
	findings := []model.Finding{}

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

	for _, rule := range snapshot.SudoRules {
		if !sudoRuleTargetsOperationalPrincipal(rule) || !rule.AllCommands {
			continue
		}

		severity := model.SeverityHigh
		if rule.NoPassword {
			severity = model.SeverityCritical
		}

		evidence := []model.Evidence{
			{Label: "path", Detail: rule.Path},
			{Label: "principal", Detail: rule.Principal},
		}
		if rule.RunAs != "" {
			evidence = append(evidence, model.Evidence{Label: "run_as", Detail: rule.RunAs})
		}
		if rule.NoPassword {
			evidence = append(evidence, model.Evidence{Label: "auth", Detail: "NOPASSWD"})
		}

		findings = append(findings, model.Finding{
			ID:          buildFindingID(operationalHardeningCheckID, "broad_sudo", rule.Path+"."+rule.Principal),
			CheckID:     operationalHardeningCheckID,
			Class:       model.FindingClassDirect,
			Severity:    severity,
			Confidence:  model.ConfidenceConfirmed,
			Title:       "Operational principal has broad sudo access",
			Why:         "Broad sudo for deploy or runtime-adjacent identities weakens separation between deploy, app runtime, and host administration duties.",
			Remediation: "Limit sudo to exact operational commands that are genuinely required and avoid granting ALL privileges to deploy or web-adjacent identities.",
			Evidence:    evidence,
			Affected:    []model.Target{{Type: "path", Path: rule.Path}},
		})
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
