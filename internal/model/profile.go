package model

import (
	"path/filepath"
	"slices"
	"strings"
	"time"
)

type HostProfile struct {
	Name     string
	OSFamily string
	Paths    DiscoveryPaths
	Switches DiscoverySwitches
}

type DiscoveryPaths struct {
	UseDefaultPatterns       bool
	AppScanRoots             []string
	NginxConfigPatterns      []string
	PHPFPMPoolPatterns       []string
	SupervisorConfigPatterns []string
	SystemdUnitPatterns      []string
}

type DiscoverySwitches struct {
	DiscoverNginx      bool
	DiscoverPHPFPM     bool
	DiscoverSupervisor bool
	DiscoverSystemd    bool
}

func IsSupportedOSFamily(osFamily string) bool {
	switch strings.ToLower(strings.TrimSpace(osFamily)) {
	case "", "auto", "custom", "ubuntu", "debian", "fedora", "rhel", "centos", "rocky", "almalinux":
		return true
	default:
		return false
	}
}

func DefaultAuditConfig() AuditConfig {
	return AuditConfig{
		Format:         OutputFormatTerminal,
		CommandTimeout: 2 * time.Second,
		MaxOutputBytes: 64 * 1024,
		Verbosity:      VerbosityNormal,
		Scope:          ScanScopeAuto,
		ColorMode:      ColorModeAuto,
		Profile: HostProfile{
			OSFamily: "auto",
			Paths: DiscoveryPaths{
				UseDefaultPatterns: true,
			},
			Switches: DiscoverySwitches{
				DiscoverNginx:      true,
				DiscoverPHPFPM:     true,
				DiscoverSupervisor: true,
				DiscoverSystemd:    true,
			},
		},
	}
}

func (config AuditConfig) NormalizedProfileName() string {
	return strings.TrimSpace(config.Profile.Name)
}

func (config AuditConfig) NormalizedOSFamily() string {
	normalizedFamily := strings.ToLower(strings.TrimSpace(config.Profile.OSFamily))
	if normalizedFamily == "" {
		return "auto"
	}

	switch normalizedFamily {
	case "debian", "ubuntu":
		return "debian"
	case "rhel", "fedora", "centos", "rocky", "almalinux":
		return "rhel"
	case "custom":
		return "custom"
	default:
		return normalizedFamily
	}
}

func (config AuditConfig) NormalizedAppScanRoots() []string {
	return normalizePaths(append([]string{}, config.Profile.Paths.AppScanRoots...))
}

func (config AuditConfig) EffectiveScanRoots() []string {
	combinedRoots := append([]string{}, config.NormalizedAppScanRoots()...)
	combinedRoots = append(combinedRoots, config.NormalizedScanRoots()...)

	return normalizePaths(combinedRoots)
}

func (config AuditConfig) NormalizedNginxConfigPatterns() []string {
	return config.effectivePatternList(defaultNginxConfigPatterns(config.NormalizedOSFamily()), config.Profile.Paths.NginxConfigPatterns)
}

func (config AuditConfig) NormalizedPHPFPMPoolPatterns() []string {
	return config.effectivePatternList(defaultPHPFPMPoolPatterns(config.NormalizedOSFamily()), config.Profile.Paths.PHPFPMPoolPatterns)
}

func (config AuditConfig) NormalizedSupervisorConfigPatterns() []string {
	return config.effectivePatternList(defaultSupervisorConfigPatterns(config.NormalizedOSFamily()), config.Profile.Paths.SupervisorConfigPatterns)
}

func (config AuditConfig) NormalizedSystemdUnitPatterns() []string {
	return config.effectivePatternList(defaultSystemdUnitPatterns(config.NormalizedOSFamily()), config.Profile.Paths.SystemdUnitPatterns)
}

func (config AuditConfig) ShouldDiscoverNginx() bool {
	return config.Profile.Switches.DiscoverNginx
}

func (config AuditConfig) ShouldDiscoverPHPFPM() bool {
	return config.Profile.Switches.DiscoverPHPFPM
}

func (config AuditConfig) effectivePatternList(defaultPatterns []string, configuredPatterns []string) []string {
	patterns := []string{}
	if config.Profile.Paths.UseDefaultPatterns {
		patterns = append(patterns, defaultPatterns...)
	}

	patterns = append(patterns, configuredPatterns...)

	return normalizePaths(patterns)
}

func normalizePaths(paths []string) []string {
	normalizedPaths := make([]string, 0, len(paths))
	seenPaths := map[string]struct{}{}

	for _, path := range paths {
		trimmedPath := strings.TrimSpace(path)
		if trimmedPath == "" {
			continue
		}

		cleanPath := trimmedPath
		if strings.ContainsAny(trimmedPath, "*?[") {
			cleanPath = filepath.Clean(trimmedPath)
			if strings.HasSuffix(trimmedPath, string(filepath.Separator)+"*") && !strings.HasSuffix(cleanPath, string(filepath.Separator)+"*") {
				cleanPath += string(filepath.Separator) + "*"
			}
		} else {
			cleanPath = filepath.Clean(trimmedPath)
		}

		if _, alreadySeen := seenPaths[cleanPath]; alreadySeen {
			continue
		}

		seenPaths[cleanPath] = struct{}{}
		normalizedPaths = append(normalizedPaths, cleanPath)
	}

	slices.Sort(normalizedPaths)

	return normalizedPaths
}

func defaultNginxConfigPatterns(osFamily string) []string {
	return []string{
		"/etc/nginx/nginx.conf",
		"/etc/nginx/conf.d/*.conf",
		"/etc/nginx/sites-enabled/*",
		"/usr/local/etc/nginx/nginx.conf",
		"/usr/local/etc/nginx/conf.d/*.conf",
		"/usr/local/etc/nginx/servers/*",
	}
}

func defaultPHPFPMPoolPatterns(osFamily string) []string {
	switch osFamily {
	case "debian":
		return []string{
			"/etc/php/*/fpm/pool.d/*.conf",
			"/usr/local/etc/php-fpm.d/*.conf",
		}
	case "rhel":
		return []string{
			"/etc/php-fpm.d/*.conf",
			"/usr/local/etc/php-fpm.d/*.conf",
		}
	default:
		return []string{
			"/etc/php/*/fpm/pool.d/*.conf",
			"/etc/php-fpm.d/*.conf",
			"/usr/local/etc/php-fpm.d/*.conf",
		}
	}
}

func defaultSupervisorConfigPatterns(osFamily string) []string {
	switch osFamily {
	case "rhel":
		return []string{
			"/etc/supervisord.conf",
			"/etc/supervisord.d/*.ini",
			"/etc/supervisor/conf.d/*.conf",
		}
	default:
		return []string{
			"/etc/supervisor/supervisord.conf",
			"/etc/supervisor/conf.d/*.conf",
			"/etc/supervisord.conf",
			"/etc/supervisord.d/*.ini",
		}
	}
}

func defaultSystemdUnitPatterns(osFamily string) []string {
	return []string{
		"/etc/systemd/system/*.service",
		"/usr/lib/systemd/system/*.service",
		"/lib/systemd/system/*.service",
	}
}
