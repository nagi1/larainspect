package discovery

import (
	"errors"
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

func (service SnapshotService) discoverNginxSites() ([]model.NginxSite, []model.Unknown) {
	configFiles, unknowns := service.readConfigFilesFromPatterns(appDiscoveryCheckID, "Unable to read Nginx config", service.nginxPatterns)
	sites := []model.NginxSite{}

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

func (service SnapshotService) discoverPHPFPMPools() ([]model.PHPFPMPool, []model.Unknown) {
	configFiles, unknowns := service.readConfigFilesFromPatterns(appDiscoveryCheckID, "Unable to read PHP-FPM pool config", service.phpFPMPatterns)
	pools := []model.PHPFPMPool{}

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

func (service SnapshotService) readConfigFilesFromPatterns(checkID string, title string, patterns []string) ([]discoveredConfigFile, []model.Unknown) {
	discoveredFiles := []discoveredConfigFile{}
	unknowns := []model.Unknown{}
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
