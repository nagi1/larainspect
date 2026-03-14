package discovery

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/nagi1/larainspect/internal/model"
)

func parseSupervisorConfig(configPath string, contents string) ([]model.SupervisorProgram, []model.SupervisorHTTPServer, error) {
	programs := []model.SupervisorProgram{}
	httpServers := []model.SupervisorHTTPServer{}
	var currentProgram *model.SupervisorProgram
	var currentHTTPServer *model.SupervisorHTTPServer

	flushSection := func() {
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
			flushSection()

			_, nextProgram, nextHTTPServer, parseErr := parseSupervisorSectionHeader(configPath, line)
			if parseErr != nil {
				return nil, nil, parseErr
			}
			currentProgram = nextProgram
			currentHTTPServer = nextHTTPServer
			continue
		}

		directiveName, directiveValue, foundSeparator := parseDirectiveLine(line)
		if !foundSeparator {
			continue
		}

		switch {
		case currentProgram != nil:
			applySupervisorProgramDirective(currentProgram, directiveName, directiveValue)
		case currentHTTPServer != nil:
			applySupervisorHTTPDirective(currentHTTPServer, directiveName, directiveValue)
		}
	}

	flushSection()
	return programs, httpServers, nil
}

func parseSupervisorSectionHeader(configPath string, line string) (string, *model.SupervisorProgram, *model.SupervisorHTTPServer, error) {
	sectionName := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "["), "]"))
	if strings.HasPrefix(sectionName, "program:") {
		programName := strings.TrimSpace(strings.TrimPrefix(sectionName, "program:"))
		if programName == "" {
			return "", nil, nil, fmt.Errorf("supervisor program section in %s is missing a name", configPath)
		}

		return sectionName, &model.SupervisorProgram{
			ConfigPath: configPath,
			Name:       programName,
		}, nil, nil
	}

	if sectionName == "inet_http_server" {
		return sectionName, nil, &model.SupervisorHTTPServer{ConfigPath: configPath}, nil
	}

	return sectionName, nil, nil, nil
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

		directiveName, directiveValue, foundSeparator := parseDirectiveLine(line)
		if !foundSeparator {
			continue
		}

		applySystemdDirective(&unit, currentSection, directiveName, directiveValue)
	}

	unit.ReadWritePaths = sortCompactStringSlice(unit.ReadWritePaths)
	unit.WantedBy = sortCompactStringSlice(unit.WantedBy)
	return unit, nil
}

func applySystemdDirective(unit *model.SystemdUnit, section string, directiveName string, directiveValue string) {
	switch section {
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

func parseDirectiveLine(line string) (string, string, bool) {
	key, value, foundSeparator := strings.Cut(line, "=")
	if !foundSeparator {
		return "", "", false
	}

	return strings.TrimSpace(key), strings.TrimSpace(value), true
}

func trimINICommentLine(rawLine string) string {
	trimmedLine := strings.TrimSpace(rawLine)
	if trimmedLine == "" || strings.HasPrefix(trimmedLine, ";") || strings.HasPrefix(trimmedLine, "#") {
		return ""
	}

	return trimmedLine
}

func sortCompactStringSlice(values []string) []string {
	slices.Sort(values)
	return slices.Compact(values)
}
