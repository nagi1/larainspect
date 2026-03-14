package discovery

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/nagi1/larainspect/internal/model"
)

func (service SnapshotService) anyCommandAvailable(commands []string) bool {
	for _, commandName := range commands {
		if strings.TrimSpace(commandName) == "" {
			continue
		}
		if _, err := service.lookPath(commandName); err == nil {
			return true
		}
	}

	return false
}

func (service SnapshotService) commandHintUnknowns(
	checkID string,
	configuredTitle string,
	fallbackTitle string,
	configKey string,
	commandLabel string,
	commands []string,
	discoveredPaths []string,
) []model.Unknown {
	if !service.commandsEnabled {
		return nil
	}

	normalizedCommands := normalizeCommandHints(commands)
	if len(normalizedCommands) == 0 || service.anyCommandAvailable(normalizedCommands) {
		return nil
	}

	if commandsUseExplicitPaths(normalizedCommands) {
		return []model.Unknown{newConfiguredCommandMissingUnknown(checkID, configuredTitle, configKey, normalizedCommands)}
	}
	if len(discoveredPaths) == 0 {
		return nil
	}

	return []model.Unknown{newCommandFallbackUnknown(checkID, fallbackTitle, configKey, commandLabel, normalizedCommands, discoveredPaths)}
}

func newConfiguredCommandMissingUnknown(checkID string, title string, configKey string, commands []string) model.Unknown {
	normalizedCommands := normalizeCommandHints(commands)
	unknown := model.Unknown{
		ID:      buildUnknownID(checkID, title, strings.Join(normalizedCommands, ",")),
		CheckID: checkID,
		Title:   title,
		Reason:  fmt.Sprintf("None of the configured commands are executable on this host; update %s to the correct full path or paths", configKey),
		Error:   model.ErrorKindCommandMissing,
	}

	for _, commandName := range normalizedCommands {
		unknown.Evidence = append(unknown.Evidence, model.Evidence{
			Label:  "command",
			Detail: commandName,
		})
	}

	return unknown
}

func newCommandFallbackUnknown(checkID string, title string, configKey string, commandLabel string, commands []string, discoveredPaths []string) model.Unknown {
	normalizedCommands := normalizeCommandHints(commands)
	unknown := model.Unknown{
		ID:      buildUnknownID(checkID, title, strings.Join(normalizedCommands, ",")),
		CheckID: checkID,
		Title:   title,
		Reason:  fmt.Sprintf("Found matching config files, but none of the expected %s commands were executable on PATH; set %s to the correct full path or paths for this host", commandLabel, configKey),
		Error:   model.ErrorKindCommandMissing,
	}

	for _, commandName := range normalizedCommands {
		unknown.Evidence = append(unknown.Evidence, model.Evidence{
			Label:  "command",
			Detail: commandName,
		})
	}
	for _, path := range normalizeCommandHints(discoveredPaths) {
		unknown.Evidence = append(unknown.Evidence, model.Evidence{
			Label:  "path",
			Detail: path,
		})
	}

	return unknown
}

func normalizeCommandHints(values []string) []string {
	normalized := make([]string, 0, len(values))
	seen := map[string]struct{}{}

	for _, value := range values {
		trimmedValue := strings.TrimSpace(value)
		if trimmedValue == "" {
			continue
		}

		cleanValue := trimmedValue
		if strings.ContainsAny(trimmedValue, "*?[") {
			cleanValue = filepath.Clean(trimmedValue)
			if strings.HasSuffix(trimmedValue, string(filepath.Separator)+"*") && !strings.HasSuffix(cleanValue, string(filepath.Separator)+"*") {
				cleanValue += string(filepath.Separator) + "*"
			}
		} else if strings.Contains(trimmedValue, string(filepath.Separator)) {
			cleanValue = filepath.Clean(trimmedValue)
		}

		if _, found := seen[cleanValue]; found {
			continue
		}
		seen[cleanValue] = struct{}{}
		normalized = append(normalized, cleanValue)
	}

	slices.Sort(normalized)
	return normalized
}

func commandsUseExplicitPaths(commands []string) bool {
	for _, commandName := range commands {
		if strings.ContainsRune(commandName, filepath.Separator) {
			return true
		}
	}

	return false
}

func configFilePaths(files []discoveredConfigFile) []string {
	paths := make([]string, 0, len(files))
	for _, configFile := range files {
		paths = append(paths, configFile.path)
	}

	return paths
}
