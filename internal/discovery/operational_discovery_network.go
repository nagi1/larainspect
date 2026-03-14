package discovery

import (
	"fmt"
	"slices"
	"strings"

	"github.com/nagi1/larainspect/internal/model"
)

func parseListenerRecords(contents string) ([]model.ListenerRecord, error) {
	records := make([]model.ListenerRecord, 0, 16)

	for lineNumber, rawLine := range strings.Split(contents, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}

		record, parseErr := parseListenerRecordLine(lineNumber, line)
		if parseErr != nil {
			return nil, parseErr
		}

		records = append(records, record)
	}

	return records, nil
}

func parseListenerRecordLine(lineNumber int, line string) (model.ListenerRecord, error) {
	fields := strings.Fields(line)
	if len(fields) < 5 {
		return model.ListenerRecord{}, fmt.Errorf("listener line %d is incomplete", lineNumber+1)
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

	return record, nil
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

	for index, segment := range strings.Split(value, "\"") {
		if index%2 == 0 {
			continue
		}

		processName := strings.TrimSpace(segment)
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
