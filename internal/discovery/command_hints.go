package discovery

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"slices"
	"strings"

	"github.com/nagi1/larainspect/internal/model"
)

func (service SnapshotService) anyCommandAvailable(commands []string) bool {
	for _, commandName := range commands {
		if service.commandAvailable(commandName) {
			return true
		}
	}

	return false
}

func (service SnapshotService) commandAvailable(commandName string) bool {
	trimmedCommand := strings.TrimSpace(commandName)
	if trimmedCommand == "" {
		return false
	}

	if service.lookPath != nil {
		if _, err := service.lookPath(trimmedCommand); err == nil {
			return true
		}
	}

	if strings.ContainsRune(trimmedCommand, filepath.Separator) {
		return service.pathLooksExecutable(filepath.Clean(trimmedCommand))
	}

	return false
}

func (service SnapshotService) resolveCommandPath(commandName string) string {
	trimmedCommand := strings.TrimSpace(commandName)
	if trimmedCommand == "" {
		return ""
	}

	if service.lookPath != nil {
		if resolvedPath, err := service.lookPath(trimmedCommand); err == nil {
			return resolvedPath
		}
	}

	if strings.ContainsRune(trimmedCommand, filepath.Separator) {
		cleanPath := filepath.Clean(trimmedCommand)
		if service.pathLooksExecutable(cleanPath) {
			return cleanPath
		}

		return ""
	}

	for _, candidatePath := range implicitCommandFallbackCandidates(trimmedCommand) {
		if service.pathLooksExecutable(candidatePath) {
			return candidatePath
		}
	}

	return ""
}

func (service SnapshotService) anyImplicitCommandFallbackAvailable(commands []string) bool {
	for _, commandName := range commands {
		trimmedCommand := strings.TrimSpace(commandName)
		if trimmedCommand == "" || strings.ContainsRune(trimmedCommand, filepath.Separator) {
			continue
		}

		for _, candidatePath := range implicitCommandFallbackCandidates(trimmedCommand) {
			if service.pathLooksExecutable(candidatePath) {
				return true
			}
		}
	}

	return false
}

func (service SnapshotService) pathLooksExecutable(path string) bool {
	if service.statPath == nil {
		return false
	}

	info, err := service.statPath(path)
	if err != nil || info == nil || info.IsDir() {
		return false
	}

	mode := info.Mode()
	if mode&fs.ModePerm == 0 {
		return true
	}

	return mode&0o111 != 0
}

func commandFallbackCandidates(commandName string) []string {
	trimmedCommand := strings.TrimSpace(commandName)
	if trimmedCommand == "" {
		return nil
	}

	if strings.ContainsRune(trimmedCommand, filepath.Separator) {
		return []string{filepath.Clean(trimmedCommand)}
	}

	switch trimmedCommand {
	case "nginx":
		return []string{
			"/usr/sbin/nginx",
			"/usr/local/sbin/nginx",
			"/usr/local/nginx/sbin/nginx",
			"/www/server/nginx/sbin/nginx",
		}
	case "supervisord":
		return []string{
			"/usr/bin/supervisord",
			"/usr/local/bin/supervisord",
			"/usr/sbin/supervisord",
			"/usr/local/sbin/supervisord",
			"/www/server/panel/pyenv/bin/supervisord",
		}
	default:
		if phpFPMCandidates := phpFPMFallbackCandidates(trimmedCommand); len(phpFPMCandidates) != 0 {
			return phpFPMCandidates
		}
	}

	return nil
}

func implicitCommandFallbackCandidates(commandName string) []string {
	candidates := commandFallbackCandidates(commandName)
	implicitCandidates := make([]string, 0, len(candidates))

	for _, candidatePath := range candidates {
		if isImplicitCommandFallbackCandidate(candidatePath) {
			implicitCandidates = append(implicitCandidates, candidatePath)
		}
	}

	return implicitCandidates
}

func isImplicitCommandFallbackCandidate(path string) bool {
	cleanPath := filepath.Clean(path)
	return strings.HasPrefix(cleanPath, "/www/server/")
}

func phpFPMFallbackCandidates(commandName string) []string {
	versionHints := phpFPMVersionHints(commandName)
	if len(versionHints) == 0 {
		return nil
	}

	candidates := []string{}
	for _, version := range versionHints {
		if version == "" {
			candidates = append(candidates,
				"/usr/sbin/php-fpm",
				"/usr/local/sbin/php-fpm",
			)
			continue
		}

		candidates = append(candidates,
			"/usr/sbin/php-fpm"+version,
			"/usr/local/sbin/php-fpm"+version,
			"/usr/sbin/php-fpm"+strings.ReplaceAll(version, ".", ""),
			"/usr/local/sbin/php-fpm"+strings.ReplaceAll(version, ".", ""),
			"/www/server/php/"+strings.ReplaceAll(version, ".", "")+"/sbin/php-fpm",
		)
	}

	return normalizeCommandHints(candidates)
}

func phpFPMVersionHints(commandName string) []string {
	switch commandName {
	case "php-fpm":
		return []string{"", "8.5", "8.4", "8.3", "8.2", "8.1", "8.0", "7.4"}
	case "php-fpm8.5", "php-fpm85":
		return []string{"8.5"}
	case "php-fpm8.4", "php-fpm84":
		return []string{"8.4"}
	case "php-fpm8.3", "php-fpm83":
		return []string{"8.3"}
	case "php-fpm8.2", "php-fpm82":
		return []string{"8.2"}
	case "php-fpm8.1", "php-fpm81":
		return []string{"8.1"}
	case "php-fpm8.0", "php-fpm80":
		return []string{"8.0"}
	case "php-fpm7.4", "php-fpm74":
		return []string{"7.4"}
	default:
		return nil
	}
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

	if !commandsUseExplicitPaths(normalizedCommands) && service.anyImplicitCommandFallbackAvailable(normalizedCommands) {
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
