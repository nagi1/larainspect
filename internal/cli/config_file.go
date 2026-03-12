package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nagi1/larainspect/internal/model"
)

type fileConfig struct {
	Version  *int                `json:"version,omitempty"`
	Server   *fileServerConfig   `json:"server,omitempty"`
	Laravel  *fileLaravelConfig  `json:"laravel,omitempty"`
	Services *fileServicesConfig `json:"services,omitempty"`
	Output   *fileOutputConfig   `json:"output,omitempty"`
	Advanced *fileAdvancedConfig `json:"advanced,omitempty"`
	Audit    *fileAuditConfig    `json:"audit,omitempty"`
	Profile  *fileProfileConfig  `json:"profile,omitempty"`
	Paths    *filePathsConfig    `json:"paths,omitempty"`
	Switches *fileSwitchesConfig `json:"switches,omitempty"`
}

type fileServerConfig struct {
	Name *string `json:"name,omitempty"`
	OS   *string `json:"os,omitempty"`
}

type fileLaravelConfig struct {
	Scope     *string  `json:"scope,omitempty"`
	AppPath   *string  `json:"app_path,omitempty"`
	ScanRoots []string `json:"scan_roots,omitempty"`
}

type fileServicesConfig struct {
	UseDefaultPaths *bool             `json:"use_default_paths,omitempty"`
	Nginx           *fileServicePaths `json:"nginx,omitempty"`
	PHPFPM          *fileServicePaths `json:"php_fpm,omitempty"`
	Supervisor      *fileServicePaths `json:"supervisor,omitempty"`
	Systemd         *fileServicePaths `json:"systemd,omitempty"`
}

type fileServicePaths struct {
	Enabled *bool    `json:"enabled,omitempty"`
	Paths   []string `json:"paths,omitempty"`
}

type fileOutputConfig struct {
	Format       *string `json:"format,omitempty"`
	Verbosity    *string `json:"verbosity,omitempty"`
	Interactive  *bool   `json:"interactive,omitempty"`
	Color        *string `json:"color,omitempty"`
	ScreenReader *bool   `json:"screen_reader,omitempty"`
}

type fileAdvancedConfig struct {
	CommandTimeout *string `json:"command_timeout,omitempty"`
	MaxOutputBytes *int    `json:"max_output_bytes,omitempty"`
	WorkerLimit    *int    `json:"worker_limit,omitempty"`
}

type fileAuditConfig struct {
	Format         *string  `json:"format,omitempty"`
	Verbosity      *string  `json:"verbosity,omitempty"`
	Scope          *string  `json:"scope,omitempty"`
	AppPath        *string  `json:"app_path,omitempty"`
	ScanRoots      []string `json:"scan_roots,omitempty"`
	Interactive    *bool    `json:"interactive,omitempty"`
	Color          *string  `json:"color,omitempty"`
	ScreenReader   *bool    `json:"screen_reader,omitempty"`
	CommandTimeout *string  `json:"command_timeout,omitempty"`
	MaxOutputBytes *int     `json:"max_output_bytes,omitempty"`
	WorkerLimit    *int     `json:"worker_limit,omitempty"`
}

type fileProfileConfig struct {
	Name     *string `json:"name,omitempty"`
	OSFamily *string `json:"os_family,omitempty"`
}

type filePathsConfig struct {
	UseDefaultPatterns       *bool    `json:"use_default_patterns,omitempty"`
	AppScanRoots             []string `json:"app_scan_roots,omitempty"`
	NginxConfigPatterns      []string `json:"nginx_config_patterns,omitempty"`
	PHPFPMPoolPatterns       []string `json:"php_fpm_pool_patterns,omitempty"`
	SupervisorConfigPatterns []string `json:"supervisor_config_patterns,omitempty"`
	SystemdUnitPatterns      []string `json:"systemd_unit_patterns,omitempty"`
}

type fileSwitchesConfig struct {
	DiscoverNginx      *bool `json:"discover_nginx,omitempty"`
	DiscoverPHPFPM     *bool `json:"discover_php_fpm,omitempty"`
	DiscoverSupervisor *bool `json:"discover_supervisor,omitempty"`
	DiscoverSystemd    *bool `json:"discover_systemd,omitempty"`
}

func resolveAuditConfigFilePath(explicitPath string) (string, error) {
	trimmedPath := strings.TrimSpace(explicitPath)
	if trimmedPath != "" {
		cleanPath := filepath.Clean(trimmedPath)
		if _, err := os.Stat(cleanPath); err != nil {
			return "", err
		}

		return cleanPath, nil
	}

	for _, candidatePath := range defaultAuditConfigPaths() {
		if _, err := os.Stat(candidatePath); err == nil {
			return candidatePath, nil
		} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return "", err
		}
	}

	return "", nil
}

func defaultAuditConfigPaths() []string {
	return []string{
		filepath.Clean("larainspect.json"),
		filepath.Clean(".larainspect.json"),
		"/etc/larainspect/config.json",
	}
}

func loadAuditConfigFile(path string) (model.AuditConfig, error) {
	fileBytes, err := os.ReadFile(path)
	if err != nil {
		return model.AuditConfig{}, err
	}

	var parsedConfig fileConfig
	decoder := json.NewDecoder(bytes.NewReader(fileBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&parsedConfig); err != nil {
		return model.AuditConfig{}, fmt.Errorf("parse config file %q: %w", path, err)
	}
	if err := decoder.Decode(&struct{}{}); err != nil && !errors.Is(err, io.EOF) {
		return model.AuditConfig{}, fmt.Errorf("parse config file %q: multiple JSON values are not allowed", path)
	}

	if parsedConfig.Version != nil && *parsedConfig.Version != 1 {
		return model.AuditConfig{}, fmt.Errorf("unsupported config version %d", *parsedConfig.Version)
	}

	config := model.DefaultAuditConfig()
	config.ConfigPath = path

	if parsedConfig.Audit != nil {
		if err := applyAuditSection(&config, *parsedConfig.Audit); err != nil {
			return model.AuditConfig{}, err
		}
	}

	if parsedConfig.Profile != nil {
		applyProfileSection(&config, *parsedConfig.Profile)
	}

	if parsedConfig.Paths != nil {
		applyPathsSection(&config, *parsedConfig.Paths)
	}

	if parsedConfig.Switches != nil {
		applySwitchesSection(&config, *parsedConfig.Switches)
	}

	if parsedConfig.Server != nil {
		applyServerSection(&config, *parsedConfig.Server)
	}
	if parsedConfig.Laravel != nil {
		applyLaravelSection(&config, *parsedConfig.Laravel)
	}
	if parsedConfig.Services != nil {
		applyServicesSection(&config, *parsedConfig.Services)
	}
	if parsedConfig.Output != nil {
		applyOutputSection(&config, *parsedConfig.Output)
	}
	if parsedConfig.Advanced != nil {
		if err := applyAdvancedSection(&config, *parsedConfig.Advanced); err != nil {
			return model.AuditConfig{}, err
		}
	}

	return config, nil
}

func applyServerSection(config *model.AuditConfig, serverConfig fileServerConfig) {
	if serverConfig.Name != nil {
		config.Profile.Name = strings.TrimSpace(*serverConfig.Name)
	}
	if serverConfig.OS != nil {
		config.Profile.OSFamily = strings.TrimSpace(*serverConfig.OS)
	}
}

func applyLaravelSection(config *model.AuditConfig, laravelConfig fileLaravelConfig) {
	if laravelConfig.Scope != nil {
		config.Scope = model.ScanScope(strings.ToLower(strings.TrimSpace(*laravelConfig.Scope)))
	}
	if laravelConfig.AppPath != nil {
		config.AppPath = strings.TrimSpace(*laravelConfig.AppPath)
	}
	if laravelConfig.ScanRoots != nil {
		config.Profile.Paths.AppScanRoots = append([]string{}, laravelConfig.ScanRoots...)
	}
}

func applyServicesSection(config *model.AuditConfig, servicesConfig fileServicesConfig) {
	if servicesConfig.UseDefaultPaths != nil {
		config.Profile.Paths.UseDefaultPatterns = *servicesConfig.UseDefaultPaths
	}

	applyServicePathConfig(&config.Profile.Switches.DiscoverNginx, &config.Profile.Paths.NginxConfigPatterns, servicesConfig.Nginx)
	applyServicePathConfig(&config.Profile.Switches.DiscoverPHPFPM, &config.Profile.Paths.PHPFPMPoolPatterns, servicesConfig.PHPFPM)
	applyServicePathConfig(&config.Profile.Switches.DiscoverSupervisor, &config.Profile.Paths.SupervisorConfigPatterns, servicesConfig.Supervisor)
	applyServicePathConfig(&config.Profile.Switches.DiscoverSystemd, &config.Profile.Paths.SystemdUnitPatterns, servicesConfig.Systemd)
}

func applyServicePathConfig(enabled *bool, paths *[]string, serviceConfig *fileServicePaths) {
	if serviceConfig == nil {
		return
	}
	if serviceConfig.Enabled != nil {
		*enabled = *serviceConfig.Enabled
	}
	if serviceConfig.Paths != nil {
		*paths = append([]string{}, serviceConfig.Paths...)
	}
}

func applyOutputSection(config *model.AuditConfig, outputConfig fileOutputConfig) {
	if outputConfig.Format != nil {
		config.Format = model.NormalizeOutputFormat(*outputConfig.Format)
	}
	if outputConfig.Verbosity != nil {
		config.Verbosity = model.Verbosity(strings.ToLower(strings.TrimSpace(*outputConfig.Verbosity)))
	}
	if outputConfig.Interactive != nil {
		config.Interactive = *outputConfig.Interactive
	}
	if outputConfig.Color != nil {
		config.ColorMode = model.ColorMode(strings.ToLower(strings.TrimSpace(*outputConfig.Color)))
	}
	if outputConfig.ScreenReader != nil {
		config.ScreenReader = *outputConfig.ScreenReader
	}
}

func applyAdvancedSection(config *model.AuditConfig, advancedConfig fileAdvancedConfig) error {
	if advancedConfig.CommandTimeout != nil {
		commandTimeout, err := time.ParseDuration(strings.TrimSpace(*advancedConfig.CommandTimeout))
		if err != nil {
			return fmt.Errorf("parse config advanced.command_timeout: %w", err)
		}
		config.CommandTimeout = commandTimeout
	}
	if advancedConfig.MaxOutputBytes != nil {
		config.MaxOutputBytes = *advancedConfig.MaxOutputBytes
	}
	if advancedConfig.WorkerLimit != nil {
		config.WorkerLimit = *advancedConfig.WorkerLimit
	}

	return nil
}

func applyAuditSection(config *model.AuditConfig, auditConfig fileAuditConfig) error {
	if auditConfig.Format != nil {
		config.Format = model.NormalizeOutputFormat(*auditConfig.Format)
	}
	if auditConfig.Verbosity != nil {
		config.Verbosity = model.Verbosity(strings.ToLower(strings.TrimSpace(*auditConfig.Verbosity)))
	}
	if auditConfig.Scope != nil {
		config.Scope = model.ScanScope(strings.ToLower(strings.TrimSpace(*auditConfig.Scope)))
	}
	if auditConfig.AppPath != nil {
		config.AppPath = strings.TrimSpace(*auditConfig.AppPath)
	}
	if auditConfig.ScanRoots != nil {
		config.ScanRoots = append([]string{}, auditConfig.ScanRoots...)
	}
	if auditConfig.Interactive != nil {
		config.Interactive = *auditConfig.Interactive
	}
	if auditConfig.Color != nil {
		config.ColorMode = model.ColorMode(strings.ToLower(strings.TrimSpace(*auditConfig.Color)))
	}
	if auditConfig.ScreenReader != nil {
		config.ScreenReader = *auditConfig.ScreenReader
	}
	if auditConfig.CommandTimeout != nil {
		commandTimeout, err := time.ParseDuration(strings.TrimSpace(*auditConfig.CommandTimeout))
		if err != nil {
			return fmt.Errorf("parse config audit.command_timeout: %w", err)
		}
		config.CommandTimeout = commandTimeout
	}
	if auditConfig.MaxOutputBytes != nil {
		config.MaxOutputBytes = *auditConfig.MaxOutputBytes
	}
	if auditConfig.WorkerLimit != nil {
		config.WorkerLimit = *auditConfig.WorkerLimit
	}

	return nil
}

func applyProfileSection(config *model.AuditConfig, profileConfig fileProfileConfig) {
	if profileConfig.Name != nil {
		config.Profile.Name = strings.TrimSpace(*profileConfig.Name)
	}
	if profileConfig.OSFamily != nil {
		config.Profile.OSFamily = strings.TrimSpace(*profileConfig.OSFamily)
	}
}

func applyPathsSection(config *model.AuditConfig, pathsConfig filePathsConfig) {
	if pathsConfig.UseDefaultPatterns != nil {
		config.Profile.Paths.UseDefaultPatterns = *pathsConfig.UseDefaultPatterns
	}
	if pathsConfig.AppScanRoots != nil {
		config.Profile.Paths.AppScanRoots = append([]string{}, pathsConfig.AppScanRoots...)
	}
	if pathsConfig.NginxConfigPatterns != nil {
		config.Profile.Paths.NginxConfigPatterns = append([]string{}, pathsConfig.NginxConfigPatterns...)
	}
	if pathsConfig.PHPFPMPoolPatterns != nil {
		config.Profile.Paths.PHPFPMPoolPatterns = append([]string{}, pathsConfig.PHPFPMPoolPatterns...)
	}
	if pathsConfig.SupervisorConfigPatterns != nil {
		config.Profile.Paths.SupervisorConfigPatterns = append([]string{}, pathsConfig.SupervisorConfigPatterns...)
	}
	if pathsConfig.SystemdUnitPatterns != nil {
		config.Profile.Paths.SystemdUnitPatterns = append([]string{}, pathsConfig.SystemdUnitPatterns...)
	}
}

func applySwitchesSection(config *model.AuditConfig, switchesConfig fileSwitchesConfig) {
	if switchesConfig.DiscoverNginx != nil {
		config.Profile.Switches.DiscoverNginx = *switchesConfig.DiscoverNginx
	}
	if switchesConfig.DiscoverPHPFPM != nil {
		config.Profile.Switches.DiscoverPHPFPM = *switchesConfig.DiscoverPHPFPM
	}
	if switchesConfig.DiscoverSupervisor != nil {
		config.Profile.Switches.DiscoverSupervisor = *switchesConfig.DiscoverSupervisor
	}
	if switchesConfig.DiscoverSystemd != nil {
		config.Profile.Switches.DiscoverSystemd = *switchesConfig.DiscoverSystemd
	}
}
