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
	Commands DiscoveryCommands
	Switches DiscoverySwitches
}

type IdentityConfig struct {
	DeployUsers   []string
	RuntimeUsers  []string
	RuntimeGroups []string
	WebUsers      []string
	WebGroups     []string
}

type DiscoveryPaths struct {
	UseDefaultPatterns       bool
	AppScanRoots             []string
	NginxConfigPatterns      []string
	PHPFPMPoolPatterns       []string
	PHPINIConfigPatterns     []string
	MySQLConfigPatterns      []string
	SupervisorConfigPatterns []string
	SystemdUnitPatterns      []string
}

type DiscoverySwitches struct {
	DiscoverNginx      bool
	DiscoverPHPFPM     bool
	DiscoverMySQL      bool
	DiscoverSupervisor bool
	DiscoverSystemd    bool
}

type DiscoveryCommands struct {
	NginxBinary      string
	PHPFPMBinaries   []string
	SupervisorBinary string
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
				DiscoverMySQL:      true,
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

func (config AuditConfig) NormalizedPHPINIConfigPatterns() []string {
	return config.effectivePatternList(defaultPHPINIConfigPatterns(config.NormalizedOSFamily()), config.Profile.Paths.PHPINIConfigPatterns)
}

func (config AuditConfig) NormalizedMySQLConfigPatterns() []string {
	return config.effectivePatternList(defaultMySQLConfigPatterns(config.NormalizedOSFamily()), config.Profile.Paths.MySQLConfigPatterns)
}

func (config AuditConfig) NormalizedSupervisorConfigPatterns() []string {
	return config.effectivePatternList(defaultSupervisorConfigPatterns(config.NormalizedOSFamily()), config.Profile.Paths.SupervisorConfigPatterns)
}

func (config AuditConfig) NormalizedNginxBinary() string {
	return strings.TrimSpace(config.Profile.Commands.NginxBinary)
}

func (config AuditConfig) NormalizedPHPFPMBinaries() []string {
	return normalizePaths(append([]string{}, config.Profile.Commands.PHPFPMBinaries...))
}

func (config AuditConfig) NormalizedSupervisorBinary() string {
	return strings.TrimSpace(config.Profile.Commands.SupervisorBinary)
}

func (config AuditConfig) NormalizedDeployUsers() []string {
	return normalizeIdentityValues(config.Identities.DeployUsers)
}

func (config AuditConfig) NormalizedRuntimeUsers() []string {
	return normalizeIdentityValues(config.Identities.RuntimeUsers)
}

func (config AuditConfig) NormalizedRuntimeGroups() []string {
	return normalizeIdentityValues(config.Identities.RuntimeGroups)
}

func (config AuditConfig) NormalizedWebUsers() []string {
	return normalizeIdentityValues(config.Identities.WebUsers)
}

func (config AuditConfig) NormalizedWebGroups() []string {
	return normalizeIdentityValues(config.Identities.WebGroups)
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

func (config AuditConfig) ShouldDiscoverMySQL() bool {
	return config.Profile.Switches.DiscoverMySQL
}

func (config AuditConfig) ShouldDiscoverSupervisor() bool {
	return config.Profile.Switches.DiscoverSupervisor
}

func (config AuditConfig) ShouldDiscoverSystemd() bool {
	return config.Profile.Switches.DiscoverSystemd
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

func normalizeIdentityValues(values []string) []string {
	if len(values) == 0 {
		return nil
	}

	normalized := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		trimmedValue := strings.TrimSpace(value)
		if trimmedValue == "" {
			continue
		}

		lookupKey := strings.ToLower(trimmedValue)
		if _, found := seen[lookupKey]; found {
			continue
		}

		seen[lookupKey] = struct{}{}
		normalized = append(normalized, trimmedValue)
	}

	slices.SortFunc(normalized, func(left string, right string) int {
		return strings.Compare(strings.ToLower(left), strings.ToLower(right))
	})

	if len(normalized) == 0 {
		return nil
	}

	return normalized
}

func defaultNginxConfigPatterns(osFamily string) []string {
	return []string{
		"/etc/nginx/nginx.conf",
		"/etc/nginx/conf.d/*.conf",
		"/etc/nginx/sites-enabled/*",
		"/usr/local/etc/nginx/nginx.conf",
		"/usr/local/etc/nginx/conf.d/*.conf",
		"/usr/local/etc/nginx/servers/*",
		"/www/server/nginx/conf/*.conf",
		"/www/server/nginx/conf/nginx.conf",
		"/www/server/nginx/conf/vhost/*.conf",
		"/www/server/nginx/src/conf/nginx.conf",
		"/www/server/panel/vhost/nginx/*.conf",
	}
}

func defaultPHPFPMPoolPatterns(osFamily string) []string {
	switch osFamily {
	case "debian":
		return []string{
			"/etc/php/*/fpm/pool.d/*.conf",
			"/usr/local/etc/php-fpm.d/*.conf",
			"/www/server/php/*/etc/php-fpm.conf",
			"/www/server/php/*/etc/php-fpm.d/*.conf",
		}
	case "rhel":
		return []string{
			"/etc/php-fpm.d/*.conf",
			"/usr/local/etc/php-fpm.d/*.conf",
			"/www/server/php/*/etc/php-fpm.conf",
			"/www/server/php/*/etc/php-fpm.d/*.conf",
		}
	default:
		return []string{
			"/etc/php/*/fpm/pool.d/*.conf",
			"/etc/php-fpm.d/*.conf",
			"/usr/local/etc/php-fpm.d/*.conf",
			"/www/server/php/*/etc/php-fpm.conf",
			"/www/server/php/*/etc/php-fpm.d/*.conf",
		}
	}
}

func defaultPHPINIConfigPatterns(osFamily string) []string {
	switch osFamily {
	case "debian":
		return []string{
			"/etc/php/*/fpm/php.ini",
			"/usr/local/etc/php/php.ini",
			"/www/server/php/*/etc/php.ini",
			"/opt/cpanel/ea-php*/root/etc/php.ini",
		}
	case "rhel":
		return []string{
			"/etc/php.ini",
			"/etc/opt/remi/php*/php.ini",
			"/usr/local/etc/php/php.ini",
			"/www/server/php/*/etc/php.ini",
			"/opt/cpanel/ea-php*/root/etc/php.ini",
		}
	default:
		return []string{
			"/etc/php/*/fpm/php.ini",
			"/etc/php.ini",
			"/etc/opt/remi/php*/php.ini",
			"/usr/local/etc/php/php.ini",
			"/www/server/php/*/etc/php.ini",
			"/opt/cpanel/ea-php*/root/etc/php.ini",
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
			"/etc/supervisor/*.conf",
			"/etc/supervisor/supervisord.conf",
			"/etc/supervisor/conf.d/*.conf",
			"/etc/supervisord.conf",
			"/etc/supervisord.d/*.ini",
		}
	}
}

func defaultMySQLConfigPatterns(osFamily string) []string {
	switch osFamily {
	case "debian":
		return []string{
			"/etc/mysql/my.cnf",
			"/etc/mysql/conf.d/*.cnf",
			"/etc/mysql/mysql.conf.d/*.cnf",
			"/etc/my.cnf",
			"/www/server/mysql/etc/my.cnf",
			"/www/server/mysql/my.cnf",
		}
	case "rhel":
		return []string{
			"/etc/my.cnf",
			"/etc/my.cnf.d/*.cnf",
			"/etc/mysql/conf.d/*.cnf",
			"/www/server/mysql/etc/my.cnf",
			"/www/server/mysql/my.cnf",
		}
	default:
		return []string{
			"/etc/mysql/my.cnf",
			"/etc/mysql/conf.d/*.cnf",
			"/etc/mysql/mysql.conf.d/*.cnf",
			"/etc/my.cnf",
			"/etc/my.cnf.d/*.cnf",
			"/www/server/mysql/etc/my.cnf",
			"/www/server/mysql/my.cnf",
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
