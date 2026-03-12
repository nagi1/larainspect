package discovery

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/nagi1/larainspect/internal/model"
)

const operationalDiscoveryCheckID = "discovery.operations"

func (service SnapshotService) discoverSupervisorConfigs() ([]model.SupervisorProgram, []model.SupervisorHTTPServer, []model.Unknown) {
	configFiles, unknowns := service.readConfigFilesFromPatterns(operationalDiscoveryCheckID, "Unable to read Supervisor config", service.supervisorPatterns)
	programs := []model.SupervisorProgram{}
	httpServers := []model.SupervisorHTTPServer{}

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
	units := []model.SystemdUnit{}

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
	entries := []model.CronEntry{}

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

func (service SnapshotService) discoverSSHConfigs() ([]model.SSHConfig, []model.Unknown) {
	configFiles, unknowns := service.readConfigFilesFromPatterns(operationalDiscoveryCheckID, "Unable to read SSH config", service.sshPatterns)
	configs := []model.SSHConfig{}

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
	rules := []model.SudoRule{}

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
	summaries := []model.FirewallSummary{}
	unknowns := []model.Unknown{}

	commandAttempts := []struct {
		command model.CommandRequest
		source  string
	}{
		{command: model.CommandRequest{Name: "ufw", Args: []string{"status"}}, source: "ufw"},
		{command: model.CommandRequest{Name: "firewall-cmd", Args: []string{"--state"}}, source: "firewalld"},
		{command: model.CommandRequest{Name: "nft", Args: []string{"list", "ruleset"}}, source: "nftables"},
		{command: model.CommandRequest{Name: "iptables", Args: []string{"-S"}}, source: "iptables"},
	}

	for _, attempt := range commandAttempts {
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

	listenerCommand := model.CommandRequest{
		Name: "ss",
		Args: []string{"-H", "-l", "-n", "-t", "-u", "-p"},
	}
	result, err := service.runCommand(ctx, listenerCommand)
	if err != nil {
		return nil, []model.Unknown{newNamedCommandUnknown("Unable to inspect listening sockets", err, "ss", commandSummary(listenerCommand))}
	}

	listeners, unknown := parseListenerCommandResult(result, listenerCommand)
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
	if parseErr != nil {
		unknown := newParseUnknown(operationalDiscoveryCheckID, "Unable to parse listener output", request.Name, parseErr)
		unknown.Evidence = []model.Evidence{{Label: "command", Detail: commandSummary(request)}}
		return nil, &unknown
	}

	return listeners, nil
}

func parseSupervisorConfig(configPath string, contents string) ([]model.SupervisorProgram, []model.SupervisorHTTPServer, error) {
	programs := []model.SupervisorProgram{}
	httpServers := []model.SupervisorHTTPServer{}
	currentSection := ""
	var currentProgram *model.SupervisorProgram
	var currentHTTPServer *model.SupervisorHTTPServer

	flush := func() {
		if currentProgram != nil {
			programs = append(programs, *currentProgram)
			currentProgram = nil
		}
		if currentHTTPServer != nil {
			httpServers = append(httpServers, *currentHTTPServer)
			currentHTTPServer = nil
		}
	}

	for _, rawLine := range strings.Split(contents, "\n") {
		line := trimINICommentLine(rawLine)
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			flush()
			currentSection = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "["), "]"))
			switch {
			case strings.HasPrefix(currentSection, "program:"):
				programName := strings.TrimSpace(strings.TrimPrefix(currentSection, "program:"))
				if programName == "" {
					return nil, nil, fmt.Errorf("supervisor program section in %s is missing a name", configPath)
				}
				currentProgram = &model.SupervisorProgram{
					ConfigPath: configPath,
					Name:       programName,
				}
			case currentSection == "inet_http_server":
				currentHTTPServer = &model.SupervisorHTTPServer{ConfigPath: configPath}
			}
			continue
		}

		key, value, foundSeparator := strings.Cut(line, "=")
		if !foundSeparator {
			continue
		}

		directiveName := strings.TrimSpace(key)
		directiveValue := strings.TrimSpace(value)
		switch {
		case currentProgram != nil:
			applySupervisorProgramDirective(currentProgram, directiveName, directiveValue)
		case currentHTTPServer != nil:
			applySupervisorHTTPDirective(currentHTTPServer, directiveName, directiveValue)
		}
	}

	flush()

	return programs, httpServers, nil
}

func applySupervisorProgramDirective(program *model.SupervisorProgram, directiveName string, directiveValue string) {
	switch directiveName {
	case "command":
		program.Command = directiveValue
	case "user":
		program.User = directiveValue
	case "directory":
		program.Directory = directiveValue
	case "autostart":
		program.AutoStart = directiveValue
	}
}

func applySupervisorHTTPDirective(server *model.SupervisorHTTPServer, directiveName string, directiveValue string) {
	switch directiveName {
	case "port":
		server.Bind = directiveValue
	case "username":
		server.Username = directiveValue
	case "password":
		server.PasswordConfigured = strings.TrimSpace(directiveValue) != ""
	}
}

func parseSystemdUnit(configPath string, contents string) (model.SystemdUnit, error) {
	unit := model.SystemdUnit{
		Path: filepath.Clean(configPath),
		Name: filepath.Base(configPath),
	}
	currentSection := ""

	for _, rawLine := range strings.Split(contents, "\n") {
		line := trimINICommentLine(rawLine)
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			currentSection = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "["), "]"))
			continue
		}

		key, value, foundSeparator := strings.Cut(line, "=")
		if !foundSeparator {
			continue
		}

		directiveName := strings.TrimSpace(key)
		directiveValue := strings.TrimSpace(value)
		switch currentSection {
		case "Unit":
			if directiveName == "Description" {
				unit.Description = directiveValue
			}
		case "Service":
			switch directiveName {
			case "User":
				unit.User = directiveValue
			case "Group":
				unit.Group = directiveValue
			case "WorkingDirectory":
				unit.WorkingDirectory = directiveValue
			case "ExecStart":
				unit.ExecStart = directiveValue
			case "NoNewPrivileges":
				unit.NoNewPrivileges = directiveValue
			case "ProtectSystem":
				unit.ProtectSystem = directiveValue
			case "ReadWritePaths":
				unit.ReadWritePaths = append(unit.ReadWritePaths, strings.Fields(directiveValue)...)
			}
		case "Install":
			if directiveName == "WantedBy" {
				unit.WantedBy = append(unit.WantedBy, strings.Fields(directiveValue)...)
			}
		}
	}

	slices.Sort(unit.ReadWritePaths)
	unit.ReadWritePaths = slices.Compact(unit.ReadWritePaths)
	slices.Sort(unit.WantedBy)
	unit.WantedBy = slices.Compact(unit.WantedBy)

	return unit, nil
}

func parseCronEntries(sourcePath string, contents string) ([]model.CronEntry, error) {
	entries := []model.CronEntry{}

	for lineNumber, rawLine := range strings.Split(contents, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if looksLikeCronEnvironmentAssignment(line) {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}

		entry := model.CronEntry{SourcePath: filepath.Clean(sourcePath)}
		if strings.HasPrefix(fields[0], "@") {
			if len(fields) < 3 {
				return nil, fmt.Errorf("cron macro line %d in %s is incomplete", lineNumber+1, sourcePath)
			}
			entry.Schedule = fields[0]
			entry.User = fields[1]
			entry.Command = strings.Join(fields[2:], " ")
		} else {
			if len(fields) < 7 {
				return nil, fmt.Errorf("cron line %d in %s is incomplete", lineNumber+1, sourcePath)
			}
			entry.Schedule = strings.Join(fields[:5], " ")
			entry.User = fields[5]
			entry.Command = strings.Join(fields[6:], " ")
		}

		entries = append(entries, entry)
	}

	return entries, nil
}

func parseCronSourceEntries(sourcePath string, contents string) ([]model.CronEntry, error) {
	cleanPath := filepath.Clean(sourcePath)
	if strings.Contains(cleanPath, "/cron.daily/") || strings.Contains(cleanPath, "/var/spool/cron/") || strings.Contains(cleanPath, "/var/spool/cron/crontabs/") {
		return parseCronScriptEntries(cleanPath, contents), nil
	}

	return parseCronEntries(cleanPath, contents)
}

func parseCronScriptEntries(sourcePath string, contents string) []model.CronEntry {
	entries := []model.CronEntry{}
	schedule := cronScheduleForScriptPath(sourcePath)
	user := cronUserForScriptPath(sourcePath)

	for _, rawLine := range strings.Split(contents, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "set ") {
			continue
		}
		if looksLikeCronEnvironmentAssignment(line) || strings.HasPrefix(line, "if ") || line == "fi" || strings.HasSuffix(line, "then") {
			continue
		}

		entries = append(entries, model.CronEntry{
			SourcePath: sourcePath,
			Schedule:   schedule,
			User:       user,
			Command:    line,
		})
	}

	return entries
}

func cronScheduleForScriptPath(sourcePath string) string {
	switch {
	case strings.Contains(sourcePath, "/cron.daily/"):
		return "@daily"
	default:
		return "@unknown"
	}
}

func cronUserForScriptPath(sourcePath string) string {
	switch {
	case strings.Contains(sourcePath, "/var/spool/cron/"):
		return filepath.Base(sourcePath)
	default:
		return "root"
	}
}

func looksLikeCronEnvironmentAssignment(line string) bool {
	key, _, foundSeparator := strings.Cut(line, "=")
	if !foundSeparator {
		return false
	}

	trimmedKey := strings.TrimSpace(key)
	return trimmedKey != "" && !strings.Contains(trimmedKey, " ")
}

func parseListenerRecords(contents string) ([]model.ListenerRecord, error) {
	records := []model.ListenerRecord{}

	for lineNumber, rawLine := range strings.Split(contents, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 5 {
			return nil, fmt.Errorf("listener line %d is incomplete", lineNumber+1)
		}

		localAddress, localPort := splitListenerAddress(fields[4])
		record := model.ListenerRecord{
			Protocol:     fields[0],
			State:        fields[1],
			LocalAddress: localAddress,
			LocalPort:    localPort,
		}

		if len(fields) > 6 {
			record.ProcessNames = extractQuotedProcessNames(strings.Join(fields[6:], " "))
		}

		records = append(records, record)
	}

	return records, nil
}

func parseSSHConfig(configPath string, contents string) (model.SSHConfig, error) {
	config := model.SSHConfig{Path: filepath.Clean(configPath)}

	for _, rawLine := range strings.Split(contents, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		key := strings.ToLower(fields[0])
		value := strings.Join(fields[1:], " ")
		switch key {
		case "permitrootlogin":
			config.PermitRootLogin = value
		case "passwordauthentication":
			config.PasswordAuthentication = value
		}
	}

	return config, nil
}

func parseSudoRules(sourcePath string, contents string) ([]model.SudoRule, error) {
	rules := []model.SudoRule{}

	for _, rawLine := range strings.Split(contents, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "Defaults") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		principal := fields[0]
		equalsIndex := strings.Index(line, "=")
		if equalsIndex < 0 {
			continue
		}

		leftSide := strings.TrimSpace(line[:equalsIndex])
		rightSide := strings.TrimSpace(line[equalsIndex+1:])
		if strings.HasPrefix(rightSide, "(") {
			closeIndex := strings.Index(rightSide, ")")
			if closeIndex >= 0 {
				rightSide = strings.TrimSpace(rightSide[closeIndex+1:])
			}
		}
		runAs := ""
		if openIndex := strings.Index(leftSide, "("); openIndex >= 0 {
			if closeIndex := strings.Index(leftSide[openIndex:], ")"); closeIndex >= 0 {
				runAs = strings.TrimSpace(leftSide[openIndex+1 : openIndex+closeIndex])
			}
		}

		noPassword := strings.Contains(rightSide, "NOPASSWD:")
		commandList := rightSide
		commandList = strings.TrimPrefix(commandList, "NOPASSWD:")
		commandList = strings.TrimPrefix(commandList, "PASSWD:")
		commandList = strings.TrimSpace(commandList)
		commands := splitCommaSeparatedCommands(commandList)

		rules = append(rules, model.SudoRule{
			Path:        filepath.Clean(sourcePath),
			Principal:   principal,
			RunAs:       runAs,
			Commands:    commands,
			NoPassword:  noPassword,
			AllCommands: len(commands) == 1 && commands[0] == "ALL",
		})
	}

	return rules, nil
}

func splitCommaSeparatedCommands(value string) []string {
	parts := strings.Split(value, ",")
	commands := make([]string, 0, len(parts))
	for _, part := range parts {
		command := strings.TrimSpace(part)
		if command == "" {
			continue
		}

		commands = append(commands, command)
	}

	return commands
}

func parseFirewallSummary(source string, result model.CommandResult) (model.FirewallSummary, bool) {
	if result.ExitCode != 0 {
		return model.FirewallSummary{}, false
	}

	output := strings.TrimSpace(result.Stdout)
	if output == "" {
		output = strings.TrimSpace(result.Stderr)
	}

	switch source {
	case "ufw":
		return model.FirewallSummary{Source: source, Enabled: !strings.Contains(strings.ToLower(output), "inactive"), State: firstOutputLine(output)}, true
	case "firewalld":
		normalizedOutput := strings.ToLower(output)
		return model.FirewallSummary{Source: source, Enabled: strings.Contains(normalizedOutput, "running"), State: firstOutputLine(output)}, true
	case "nftables", "iptables":
		return model.FirewallSummary{Source: source, Enabled: output != "", State: firstOutputLine(output)}, true
	default:
		return model.FirewallSummary{}, false
	}
}

func firstOutputLine(value string) string {
	lines := strings.Split(strings.TrimSpace(value), "\n")
	if len(lines) == 0 {
		return ""
	}

	return strings.TrimSpace(lines[0])
}

func splitListenerAddress(value string) (string, string) {
	trimmedValue := strings.TrimSpace(value)
	if trimmedValue == "" {
		return "", ""
	}

	if strings.HasPrefix(trimmedValue, "[") {
		if separatorIndex := strings.LastIndex(trimmedValue, "]:"); separatorIndex >= 0 {
			return trimmedValue[1:separatorIndex], trimmedValue[separatorIndex+2:]
		}
	}

	separatorIndex := strings.LastIndex(trimmedValue, ":")
	if separatorIndex < 0 {
		return trimmedValue, ""
	}

	return trimmedValue[:separatorIndex], trimmedValue[separatorIndex+1:]
}

func extractQuotedProcessNames(value string) []string {
	processNames := []string{}
	seenProcessNames := map[string]struct{}{}
	segments := strings.Split(value, "\"")
	for index := 1; index < len(segments); index += 2 {
		processName := strings.TrimSpace(segments[index])
		if processName == "" {
			continue
		}
		if _, seen := seenProcessNames[processName]; seen {
			continue
		}

		seenProcessNames[processName] = struct{}{}
		processNames = append(processNames, processName)
	}

	slices.Sort(processNames)

	return processNames
}

func trimINICommentLine(rawLine string) string {
	trimmedLine := strings.TrimSpace(rawLine)
	if trimmedLine == "" || strings.HasPrefix(trimmedLine, ";") || strings.HasPrefix(trimmedLine, "#") {
		return ""
	}

	return trimmedLine
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
