package discovery

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/nagi1/larainspect/internal/model"
)

const operationalDiscoveryCheckID = "discovery.operations"

func (service SnapshotService) discoverSupervisorConfigs() ([]model.SupervisorProgram, []model.SupervisorHTTPServer, []model.Unknown) {
	configFiles, unknowns := service.readConfigFilesFromPatterns(operationalDiscoveryCheckID, "Unable to read Supervisor config", service.supervisorPatterns)
	if commandName := strings.TrimSpace(service.supervisorCommand); commandName != "" {
		unknowns = append(unknowns, service.commandHintUnknowns(
			operationalDiscoveryCheckID,
			"Configured Supervisor binary was not found",
			"Supervisor binary was not found on PATH",
			"services.supervisor.binary",
			"Supervisor",
			[]string{commandName},
			configFilePaths(configFiles),
		)...)
	}
	programs := make([]model.SupervisorProgram, 0, len(configFiles)*2)
	httpServers := make([]model.SupervisorHTTPServer, 0, 2)

	for _, configFile := range configFiles {
		parsedPrograms, parsedHTTPServers, parseErr := parseSupervisorConfig(configFile.path, string(configFile.contents))
		if parseErr != nil {
			unknowns = append(unknowns, newParseUnknown(operationalDiscoveryCheckID, "Unable to parse Supervisor config", configFile.path, parseErr))
			continue
		}

		programs = append(programs, parsedPrograms...)
		httpServers = append(httpServers, parsedHTTPServers...)
	}

	model.SortSupervisorPrograms(programs)
	model.SortSupervisorHTTPServers(httpServers)

	return programs, httpServers, unknowns
}

func (service SnapshotService) discoverSystemdUnits() ([]model.SystemdUnit, []model.Unknown) {
	configFiles, unknowns := service.readConfigFilesFromPatterns(operationalDiscoveryCheckID, "Unable to read systemd unit", service.systemdPatterns)
	units := make([]model.SystemdUnit, 0, len(configFiles))

	for _, configFile := range configFiles {
		unit, parseErr := parseSystemdUnit(configFile.path, string(configFile.contents))
		if parseErr != nil {
			unknowns = append(unknowns, newParseUnknown(operationalDiscoveryCheckID, "Unable to parse systemd unit", configFile.path, parseErr))
			continue
		}

		units = append(units, unit)
	}

	model.SortSystemdUnits(units)
	return units, unknowns
}

func (service SnapshotService) discoverCronEntries() ([]model.CronEntry, []model.Unknown) {
	configFiles, unknowns := service.readConfigFilesFromPatterns(operationalDiscoveryCheckID, "Unable to read cron config", service.cronPatterns)
	entries := make([]model.CronEntry, 0, len(configFiles)*4)

	for _, configFile := range configFiles {
		parsedEntries, parseErr := parseCronSourceEntries(configFile.path, string(configFile.contents))
		if parseErr != nil {
			unknowns = append(unknowns, newParseUnknown(operationalDiscoveryCheckID, "Unable to parse cron config", configFile.path, parseErr))
			continue
		}

		entries = append(entries, parsedEntries...)
	}

	model.SortCronEntries(entries)
	return entries, unknowns
}

func (service SnapshotService) discoverPHPFPMPools() ([]model.PHPFPMPool, []model.Unknown) {
	configFiles, unknowns := service.readConfigFilesFromPatterns(appDiscoveryCheckID, "Unable to read PHP-FPM pool config", service.phpFPMPatterns)
	unknowns = append(unknowns, service.commandHintUnknowns(
		appDiscoveryCheckID,
		"Configured PHP-FPM binaries were not found",
		"PHP-FPM binaries were not found on PATH",
		"services.php_fpm.binaries",
		"PHP-FPM",
		service.phpFPMCommands,
		configFilePaths(configFiles),
	)...)

	pools := make([]model.PHPFPMPool, 0, len(configFiles))

	for _, configFile := range configFiles {
		parsedPools, parseErr := parsePHPFPMPools(configFile.path, string(configFile.contents))
		if parseErr != nil {
			unknowns = append(unknowns, newParseUnknown(appDiscoveryCheckID, "Unable to parse PHP-FPM pool config", configFile.path, parseErr))
			continue
		}

		pools = append(pools, parsedPools...)
	}

	model.SortPHPFPMPools(pools)

	return pools, unknowns
}

func (service SnapshotService) discoverSSHConfigs() ([]model.SSHConfig, []model.Unknown) {
	configFiles, unknowns := service.readConfigFilesFromPatterns(operationalDiscoveryCheckID, "Unable to read SSH config", service.sshPatterns)
	configs := make([]model.SSHConfig, 0, len(configFiles))

	for _, configFile := range configFiles {
		config, parseErr := parseSSHConfig(configFile.path, string(configFile.contents))
		if parseErr != nil {
			unknowns = append(unknowns, newParseUnknown(operationalDiscoveryCheckID, "Unable to parse SSH config", configFile.path, parseErr))
			continue
		}

		configs = append(configs, config)
	}

	model.SortSSHConfigs(configs)
	return configs, unknowns
}

func (service SnapshotService) discoverSudoRules() ([]model.SudoRule, []model.Unknown) {
	configFiles, unknowns := service.readConfigFilesFromPatterns(operationalDiscoveryCheckID, "Unable to read sudoers config", service.sudoersPatterns)
	rules := make([]model.SudoRule, 0, len(configFiles)*4)

	for _, configFile := range configFiles {
		parsedRules, parseErr := parseSudoRules(configFile.path, string(configFile.contents))
		if parseErr != nil {
			unknowns = append(unknowns, newParseUnknown(operationalDiscoveryCheckID, "Unable to parse sudoers config", configFile.path, parseErr))
			continue
		}

		rules = append(rules, parsedRules...)
	}

	model.SortSudoRules(rules)
	return rules, unknowns
}

func (service SnapshotService) discoverFirewallSummaries(ctx context.Context) ([]model.FirewallSummary, []model.Unknown) {
	summaries := make([]model.FirewallSummary, 0, 2)
	unknowns := make([]model.Unknown, 0, 2)

	for _, attempt := range firewallCommandAttempts() {
		if _, err := service.lookPath(attempt.command.Name); err != nil {
			continue
		}

		result, err := service.runCommand(ctx, attempt.command)
		if err != nil {
			unknowns = append(unknowns, newNamedCommandUnknown("Unable to inspect firewall state", err, attempt.source, commandSummary(attempt.command)))
			continue
		}

		summary, ok := parseFirewallSummary(attempt.source, result)
		if !ok {
			continue
		}

		summaries = append(summaries, summary)
	}

	model.SortFirewallSummaries(summaries)
	return summaries, unknowns
}

func (service SnapshotService) discoverListenersFromCommand(ctx context.Context) ([]model.ListenerRecord, []model.Unknown) {
	if _, err := service.lookPath("ss"); err != nil {
		return nil, nil
	}

	request := model.CommandRequest{Name: "ss", Args: []string{"-H", "-l", "-n", "-t", "-u", "-p"}}
	result, err := service.runCommand(ctx, request)
	if err != nil {
		return nil, []model.Unknown{newNamedCommandUnknown("Unable to inspect listening sockets", err, "ss", commandSummary(request))}
	}

	listeners, unknown := parseListenerCommandResult(result, request)
	if unknown != nil {
		return nil, []model.Unknown{*unknown}
	}

	model.SortListenerRecords(listeners)
	return listeners, nil
}

func parseListenerCommandResult(result model.CommandResult, request model.CommandRequest) ([]model.ListenerRecord, *model.Unknown) {
	if result.ExitCode != 0 {
		reason := strings.TrimSpace(result.Stderr)
		if reason == "" {
			reason = fmt.Sprintf("%s exited with code %d", request.Name, result.ExitCode)
		}

		return nil, &model.Unknown{
			ID:      buildUnknownID(operationalDiscoveryCheckID, "Unable to inspect listening sockets", request.Name),
			CheckID: operationalDiscoveryCheckID,
			Title:   "Unable to inspect listening sockets",
			Reason:  reason,
			Error:   model.ErrorKindCommandFailed,
			Evidence: []model.Evidence{
				{Label: "command", Detail: commandSummary(request)},
			},
		}
	}

	listeners, parseErr := parseListenerRecords(result.Stdout)
	if parseErr == nil {
		return listeners, nil
	}

	unknown := newParseUnknown(operationalDiscoveryCheckID, "Unable to parse listener output", request.Name, parseErr)
	unknown.Evidence = []model.Evidence{{Label: "command", Detail: commandSummary(request)}}
	return nil, &unknown
}

type firewallCommandAttempt struct {
	command model.CommandRequest
	source  string
}

func firewallCommandAttempts() []firewallCommandAttempt {
	return []firewallCommandAttempt{
		{command: model.CommandRequest{Name: "ufw", Args: []string{"status"}}, source: "ufw"},
		{command: model.CommandRequest{Name: "firewall-cmd", Args: []string{"--state"}}, source: "firewalld"},
		{command: model.CommandRequest{Name: "nft", Args: []string{"list", "ruleset"}}, source: "nftables"},
		{command: model.CommandRequest{Name: "iptables", Args: []string{"-S"}}, source: "iptables"},
	}
}

func newCommandUnknown(title string, err error) model.Unknown {
	return newNamedCommandUnknown(title, err, "ss", "ss -H -l -n -t -u -p")
}

func newNamedCommandUnknown(title string, err error, path string, command string) model.Unknown {
	errorKind := model.ErrorKindCommandFailed
	reason := err.Error()
	if errors.Is(err, context.DeadlineExceeded) || strings.Contains(strings.ToLower(reason), "timeout") {
		errorKind = model.ErrorKindCommandTimeout
	}

	return model.Unknown{
		ID:      buildUnknownID(operationalDiscoveryCheckID, title, path),
		CheckID: operationalDiscoveryCheckID,
		Title:   title,
		Reason:  reason,
		Error:   errorKind,
		Evidence: []model.Evidence{
			{Label: "command", Detail: command},
		},
	}
}

func commandSummary(request model.CommandRequest) string {
	if len(request.Args) == 0 {
		return request.Name
	}

	return request.Name + " " + strings.Join(request.Args, " ")
}
