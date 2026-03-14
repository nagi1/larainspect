package discovery

import (
	"fmt"
	"strings"

	"github.com/nagi1/larainspect/internal/model"
)

func parseMySQLConfigs(configPath string, contents string) ([]model.MySQLConfig, error) {
	configsBySection := map[string]*model.MySQLConfig{}
	currentSection := "global"

	ensureSection := func(section string) *model.MySQLConfig {
		if config, found := configsBySection[section]; found {
			return config
		}

		config := &model.MySQLConfig{ConfigPath: configPath, Section: section}
		configsBySection[section] = config
		return config
	}

	for _, rawLine := range strings.Split(contents, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "!include") || strings.HasPrefix(line, "!includedir") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			if !strings.HasSuffix(line, "]") {
				return nil, fmt.Errorf("mysql section header in %s is malformed", configPath)
			}
			sectionName := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "["), "]")))
			if sectionName == "" {
				return nil, fmt.Errorf("mysql section header in %s is missing a name", configPath)
			}
			currentSection = sectionName
			continue
		}

		directiveName, directiveValue, ok := splitMySQLDirective(line)
		if !ok {
			continue
		}

		config := ensureSection(currentSection)
		switch directiveName {
		case "bind-address", "bind_address":
			config.BindAddress = directiveValue
		case "port":
			config.Port = directiveValue
		case "socket":
			config.Socket = directiveValue
		case "datadir", "data-dir":
			config.DataDir = directiveValue
		case "skip-networking", "skip_networking":
			config.SkipNetworking = directiveValue == "" || directiveValue == "1" || strings.EqualFold(directiveValue, "on") || strings.EqualFold(directiveValue, "true")
		}
	}

	configs := make([]model.MySQLConfig, 0, len(configsBySection))
	for _, config := range configsBySection {
		if config.BindAddress == "" && config.Port == "" && config.Socket == "" && config.DataDir == "" && !config.SkipNetworking {
			continue
		}
		configs = append(configs, *config)
	}

	model.SortMySQLConfigs(configs)
	return configs, nil
}

func splitMySQLDirective(line string) (string, string, bool) {
	separator := strings.Index(line, "=")
	if separator >= 0 {
		name := strings.ToLower(strings.TrimSpace(line[:separator]))
		value := strings.TrimSpace(line[separator+1:])
		return name, trimMySQLDirectiveValue(value), name != ""
	}

	fields := strings.Fields(line)
	if len(fields) == 0 {
		return "", "", false
	}
	if len(fields) == 1 {
		return strings.ToLower(strings.TrimSpace(fields[0])), "", true
	}

	name := strings.ToLower(strings.TrimSpace(fields[0]))
	value := strings.TrimSpace(strings.Join(fields[1:], " "))
	return name, trimMySQLDirectiveValue(value), name != ""
}

func trimMySQLDirectiveValue(value string) string {
	trimmedValue := strings.TrimSpace(value)
	trimmedValue = strings.Trim(trimmedValue, `"'`)
	return strings.TrimSpace(trimmedValue)
}
