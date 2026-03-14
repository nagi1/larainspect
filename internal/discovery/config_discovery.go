package discovery

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"slices"
	"strings"

	"github.com/nagi1/larainspect/internal/model"
)

type discoveredConfigFile struct {
	path     string
	contents []byte
}

func (service SnapshotService) discoverNginxSites(ctx context.Context) ([]model.NginxSite, []model.Unknown) {
	if sites, unknowns, ok := service.discoverNginxSitesFromCommand(ctx); ok {
		return sites, unknowns
	}

	configFiles, unknowns := service.readConfigFilesFromPatterns(appDiscoveryCheckID, "Unable to read Nginx config", service.nginxPatterns)
	if strings.TrimSpace(service.nginxCommand) == "nginx" {
		unknowns = append(unknowns, service.commandHintUnknowns(
			appDiscoveryCheckID,
			"Configured Nginx binary was not found",
			"Nginx binary was not found on PATH",
			"services.nginx.binary",
			"Nginx",
			[]string{service.nginxCommand},
			configFilePaths(configFiles),
		)...)
	}
	sites := make([]model.NginxSite, 0, len(configFiles))

	for _, configFile := range configFiles {
		parsedSites, parseErr := parseNginxSites(configFile.path, string(configFile.contents))
		if parseErr != nil {
			unknowns = append(unknowns, newParseUnknown(appDiscoveryCheckID, "Unable to parse Nginx config", configFile.path, parseErr))
			continue
		}

		sites = append(sites, parsedSites...)
	}

	model.SortNginxSites(sites)

	return sites, unknowns
}

func (service SnapshotService) discoverNginxSitesFromCommand(ctx context.Context) ([]model.NginxSite, []model.Unknown, bool) {
	if !service.commandsEnabled {
		return nil, nil, false
	}

	commandName := strings.TrimSpace(service.nginxCommand)
	if commandName == "" {
		commandName = "nginx"
	}

	if _, err := service.lookPath(commandName); err != nil {
		if commandName != "nginx" {
			return nil, []model.Unknown{{
				ID:      buildUnknownID(appDiscoveryCheckID, "Configured Nginx binary was not found", commandName),
				CheckID: appDiscoveryCheckID,
				Title:   "Configured Nginx binary was not found",
				Reason:  fmt.Sprintf("%s is not executable or not present; update services.nginx.binary to the correct full path for this host", commandName),
				Error:   model.ErrorKindNotEnoughData,
				Evidence: []model.Evidence{
					{Label: "command", Detail: commandName},
				},
			}}, true
		}
		return nil, nil, false
	}

	request := model.CommandRequest{Name: commandName, Args: []string{"-T"}}
	result, err := service.runCommand(ctx, request)
	if err != nil {
		return nil, []model.Unknown{newNamedCommandUnknown("Unable to inspect Nginx config", err, commandName, commandSummary(request))}, true
	}
	if result.ExitCode != 0 {
		reason := strings.TrimSpace(result.Stderr)
		if reason == "" {
			reason = strings.TrimSpace(result.Stdout)
		}
		if reason == "" {
			reason = "nginx -T exited without output"
		}

		return nil, []model.Unknown{model.Unknown{
			ID:      buildUnknownID(appDiscoveryCheckID, "Unable to inspect Nginx config", commandName),
			CheckID: appDiscoveryCheckID,
			Title:   "Unable to inspect Nginx config",
			Reason:  reason,
			Error:   model.ErrorKindCommandFailed,
			Evidence: []model.Evidence{
				{Label: "command", Detail: commandSummary(request)},
			},
		}}, true
	}

	combinedOutput := strings.TrimSpace(result.Stdout)
	if combinedOutput == "" {
		combinedOutput = strings.TrimSpace(result.Stderr)
	}
	if combinedOutput == "" {
		return nil, nil, true
	}

	sites, parseErr := parseNginxSites("nginx -T", combinedOutput)
	if parseErr != nil {
		unknown := newParseUnknown(appDiscoveryCheckID, "Unable to parse Nginx config", commandName+" -T", parseErr)
		unknown.Evidence = []model.Evidence{{Label: "command", Detail: commandSummary(request)}}
		return nil, []model.Unknown{unknown}, true
	}

	model.SortNginxSites(sites)
	return sites, nil, true
}

func (service SnapshotService) readConfigFilesFromPatterns(checkID string, title string, patterns []string) ([]discoveredConfigFile, []model.Unknown) {
	discoveredFiles := make([]discoveredConfigFile, 0, len(patterns)*2)
	unknowns := make([]model.Unknown, 0, 2)
	seenPaths := map[string]struct{}{}

	for _, pattern := range patterns {
		matches, globErr := service.expandConfigPattern(pattern)
		if globErr != nil {
			unknowns = append(unknowns, newPathUnknown(checkID, title, pattern, globErr))
			continue
		}

		for _, matchedPath := range matches {
			cleanPath := filepath.Clean(matchedPath)
			if _, alreadySeen := seenPaths[cleanPath]; alreadySeen {
				continue
			}

			fileContents, readErr := service.readFile(cleanPath)
			switch {
			case readErr == nil:
				seenPaths[cleanPath] = struct{}{}
				discoveredFiles = append(discoveredFiles, discoveredConfigFile{path: cleanPath, contents: fileContents})
			case errors.Is(readErr, fs.ErrNotExist):
			default:
				unknowns = append(unknowns, newPathUnknown(checkID, title, cleanPath, readErr))
			}
		}
	}

	slices.SortFunc(discoveredFiles, func(leftFile discoveredConfigFile, rightFile discoveredConfigFile) int {
		return strings.Compare(leftFile.path, rightFile.path)
	})

	return discoveredFiles, unknowns
}

func (service SnapshotService) expandConfigPattern(pattern string) ([]string, error) {
	if !strings.ContainsAny(pattern, "*?[") {
		if _, err := service.statPath(pattern); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil, nil
			}

			return []string{pattern}, nil
		}

		return []string{pattern}, nil
	}

	matches, err := service.globPaths(pattern)
	if err != nil {
		return nil, err
	}

	return matches, nil
}
