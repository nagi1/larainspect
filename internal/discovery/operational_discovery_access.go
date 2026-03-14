package discovery

import (
	"path/filepath"
	"strings"

	"github.com/nagi1/larainspect/internal/model"
)

func parseSudoRules(sourcePath string, contents string) ([]model.SudoRule, error) {
	rules := []model.SudoRule{}

	for _, rawLine := range strings.Split(contents, "\n") {
		line := strings.TrimSpace(rawLine)
		if shouldSkipSudoLine(line) {
			continue
		}

		rule, ok := parseSudoRuleLine(sourcePath, line)
		if !ok {
			continue
		}

		rules = append(rules, rule)
	}

	return rules, nil
}

func shouldSkipSudoLine(line string) bool {
	if line == "" || strings.HasPrefix(line, "#") {
		return true
	}

	return strings.HasPrefix(line, "Defaults")
}

func parseSudoRuleLine(sourcePath string, line string) (model.SudoRule, bool) {
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return model.SudoRule{}, false
	}

	equalsIndex := strings.Index(line, "=")
	if equalsIndex < 0 {
		return model.SudoRule{}, false
	}

	leftSide := strings.TrimSpace(line[:equalsIndex])
	rightSide := strings.TrimSpace(line[equalsIndex+1:])
	runAs, normalizedRightSide := extractSudoRunAsAndCommandList(leftSide, rightSide)
	commands := splitCommaSeparatedCommands(normalizedRightSide)

	return model.SudoRule{
		Path:        filepath.Clean(sourcePath),
		Principal:   fields[0],
		RunAs:       runAs,
		Commands:    commands,
		NoPassword:  strings.Contains(rightSide, "NOPASSWD:"),
		AllCommands: len(commands) == 1 && commands[0] == "ALL",
	}, true
}

func extractSudoRunAsAndCommandList(leftSide string, rightSide string) (string, string) {
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

	commandList := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(rightSide, "NOPASSWD:"), "PASSWD:"))
	return runAs, commandList
}

func splitCommaSeparatedCommands(value string) []string {
	parts := strings.Split(value, ",")
	commands := make([]string, 0, len(parts))

	for _, part := range parts {
		command := normalizeSudoCommandToken(part)
		if command == "" {
			continue
		}

		commands = append(commands, command)
	}

	return commands
}

func normalizeSudoCommandToken(value string) string {
	command := strings.TrimSpace(value)
	for _, prefix := range []string{"NOPASSWD:", "PASSWD:"} {
		command = strings.TrimSpace(strings.TrimPrefix(command, prefix))
	}

	return command
}
