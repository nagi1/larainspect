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
	"gopkg.in/yaml.v3"
)

type fileConfig struct {
	Version  *int                `json:"version,omitempty" yaml:"version,omitempty"`
	Server   *fileServerConfig   `json:"server,omitempty" yaml:"server,omitempty"`
	Laravel  *fileLaravelConfig  `json:"laravel,omitempty" yaml:"laravel,omitempty"`
	Services *fileServicesConfig `json:"services,omitempty" yaml:"services,omitempty"`
	Output   *fileOutputConfig   `json:"output,omitempty" yaml:"output,omitempty"`
	Advanced *fileAdvancedConfig `json:"advanced,omitempty" yaml:"advanced,omitempty"`
	Audit    *fileAuditConfig    `json:"audit,omitempty" yaml:"audit,omitempty"`
	Profile  *fileProfileConfig  `json:"profile,omitempty" yaml:"profile,omitempty"`
	Paths    *filePathsConfig    `json:"paths,omitempty" yaml:"paths,omitempty"`
	Rules    *fileRulesConfig    `json:"rules,omitempty" yaml:"rules,omitempty"`
	Switches *fileSwitchesConfig `json:"switches,omitempty" yaml:"switches,omitempty"`
}

type fileServerConfig struct {
	Name *string `json:"name,omitempty" yaml:"name,omitempty"`
	OS   *string `json:"os,omitempty" yaml:"os,omitempty"`
}

type fileLaravelConfig struct {
	Scope     *string  `json:"scope,omitempty" yaml:"scope,omitempty"`
	AppPath   *string  `json:"app_path,omitempty" yaml:"app_path,omitempty"`
	ScanRoots []string `json:"scan_roots,omitempty" yaml:"scan_roots,omitempty"`
}

type fileServicesConfig struct {
	UseDefaultPaths *bool             `json:"use_default_paths,omitempty" yaml:"use_default_paths,omitempty"`
	Nginx           *fileServicePaths `json:"nginx,omitempty" yaml:"nginx,omitempty"`
	PHPFPM          *fileServicePaths `json:"php_fpm,omitempty" yaml:"php_fpm,omitempty"`
	MySQL           *fileServicePaths `json:"mysql,omitempty" yaml:"mysql,omitempty"`
	Supervisor      *fileServicePaths `json:"supervisor,omitempty" yaml:"supervisor,omitempty"`
	Systemd         *fileServicePaths `json:"systemd,omitempty" yaml:"systemd,omitempty"`
}

type fileServicePaths struct {
	Enabled  *bool    `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	Paths    []string `json:"paths,omitempty" yaml:"paths,omitempty"`
	Binary   *string  `json:"binary,omitempty" yaml:"binary,omitempty"`
	Binaries []string `json:"binaries,omitempty" yaml:"binaries,omitempty"`
}

type fileOutputConfig struct {
	Format             *string `json:"format,omitempty" yaml:"format,omitempty"`
	ReportJSONPath     *string `json:"report_json_path,omitempty" yaml:"report_json_path,omitempty"`
	ReportMarkdownPath *string `json:"report_markdown_path,omitempty" yaml:"report_markdown_path,omitempty"`
	Verbosity          *string `json:"verbosity,omitempty" yaml:"verbosity,omitempty"`
	Interactive        *bool   `json:"interactive,omitempty" yaml:"interactive,omitempty"`
	Color              *string `json:"color,omitempty" yaml:"color,omitempty"`
	ScreenReader       *bool   `json:"screen_reader,omitempty" yaml:"screen_reader,omitempty"`
}

type fileAdvancedConfig struct {
	CommandTimeout *string `json:"command_timeout,omitempty" yaml:"command_timeout,omitempty"`
	MaxOutputBytes *int    `json:"max_output_bytes,omitempty" yaml:"max_output_bytes,omitempty"`
	WorkerLimit    *int    `json:"worker_limit,omitempty" yaml:"worker_limit,omitempty"`
}

type fileAuditConfig struct {
	Format             *string  `json:"format,omitempty" yaml:"format,omitempty"`
	ReportJSONPath     *string  `json:"report_json_path,omitempty" yaml:"report_json_path,omitempty"`
	ReportMarkdownPath *string  `json:"report_markdown_path,omitempty" yaml:"report_markdown_path,omitempty"`
	DebugLogPath       *string  `json:"debug_log_path,omitempty" yaml:"debug_log_path,omitempty"`
	Verbosity          *string  `json:"verbosity,omitempty" yaml:"verbosity,omitempty"`
	Scope              *string  `json:"scope,omitempty" yaml:"scope,omitempty"`
	AppPath            *string  `json:"app_path,omitempty" yaml:"app_path,omitempty"`
	ScanRoots          []string `json:"scan_roots,omitempty" yaml:"scan_roots,omitempty"`
	Interactive        *bool    `json:"interactive,omitempty" yaml:"interactive,omitempty"`
	Color              *string  `json:"color,omitempty" yaml:"color,omitempty"`
	ScreenReader       *bool    `json:"screen_reader,omitempty" yaml:"screen_reader,omitempty"`
	CommandTimeout     *string  `json:"command_timeout,omitempty" yaml:"command_timeout,omitempty"`
	MaxOutputBytes     *int     `json:"max_output_bytes,omitempty" yaml:"max_output_bytes,omitempty"`
	WorkerLimit        *int     `json:"worker_limit,omitempty" yaml:"worker_limit,omitempty"`
	VulnCheck          *bool    `json:"vuln_check,omitempty" yaml:"vuln_check,omitempty"`
}

type fileProfileConfig struct {
	Name     *string `json:"name,omitempty" yaml:"name,omitempty"`
	OSFamily *string `json:"os_family,omitempty" yaml:"os_family,omitempty"`
}

type filePathsConfig struct {
	UseDefaultPatterns       *bool    `json:"use_default_patterns,omitempty" yaml:"use_default_patterns,omitempty"`
	AppScanRoots             []string `json:"app_scan_roots,omitempty" yaml:"app_scan_roots,omitempty"`
	NginxConfigPatterns      []string `json:"nginx_config_patterns,omitempty" yaml:"nginx_config_patterns,omitempty"`
	PHPFPMPoolPatterns       []string `json:"php_fpm_pool_patterns,omitempty" yaml:"php_fpm_pool_patterns,omitempty"`
	MySQLConfigPatterns      []string `json:"mysql_config_patterns,omitempty" yaml:"mysql_config_patterns,omitempty"`
	SupervisorConfigPatterns []string `json:"supervisor_config_patterns,omitempty" yaml:"supervisor_config_patterns,omitempty"`
	SystemdUnitPatterns      []string `json:"systemd_unit_patterns,omitempty" yaml:"systemd_unit_patterns,omitempty"`
}

type fileSwitchesConfig struct {
	DiscoverNginx      *bool `json:"discover_nginx,omitempty" yaml:"discover_nginx,omitempty"`
	DiscoverPHPFPM     *bool `json:"discover_php_fpm,omitempty" yaml:"discover_php_fpm,omitempty"`
	DiscoverMySQL      *bool `json:"discover_mysql,omitempty" yaml:"discover_mysql,omitempty"`
	DiscoverSupervisor *bool `json:"discover_supervisor,omitempty" yaml:"discover_supervisor,omitempty"`
	DiscoverSystemd    *bool `json:"discover_systemd,omitempty" yaml:"discover_systemd,omitempty"`
}

type fileRulesConfig struct {
	Enable     []string                    `json:"enable,omitempty" yaml:"enable,omitempty"`
	Disable    []string                    `json:"disable,omitempty" yaml:"disable,omitempty"`
	CustomDirs []string                    `json:"custom_dirs,omitempty" yaml:"custom_dirs,omitempty"`
	Override   map[string]fileRuleOverride `json:"override,omitempty" yaml:"override,omitempty"`
}

type fileRuleOverride struct {
	Severity   *string `json:"severity,omitempty" yaml:"severity,omitempty"`
	Confidence *string `json:"confidence,omitempty" yaml:"confidence,omitempty"`
	Enabled    *bool   `json:"enabled,omitempty" yaml:"enabled,omitempty"`
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
		filepath.Clean("larainspect.yaml"),
		filepath.Clean("larainspect.yml"),
		filepath.Clean(".larainspect.yaml"),
		filepath.Clean(".larainspect.yml"),
		filepath.Clean("larainspect.json"),
		filepath.Clean(".larainspect.json"),
		"/etc/larainspect/config.yaml",
		"/etc/larainspect/config.json",
	}
}

func isYAMLConfigFile(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".yaml", ".yml":
		return true
	default:
		return false
	}
}

func loadAuditConfigFile(path string) (model.AuditConfig, error) {
	fileBytes, err := os.ReadFile(path)
	if err != nil {
		return model.AuditConfig{}, err
	}

	var parsedConfig fileConfig
	if err := decodeConfigFile(path, fileBytes, &parsedConfig); err != nil {
		return model.AuditConfig{}, fmt.Errorf("parse config file %q: %w", path, err)
	}

	if parsedConfig.Version != nil && *parsedConfig.Version != 1 {
		return model.AuditConfig{}, fmt.Errorf("unsupported config version %d", *parsedConfig.Version)
	}

	return applyFileConfig(path, parsedConfig)
}

func decodeConfigFile(path string, data []byte, config *fileConfig) error {
	if isYAMLConfigFile(path) {
		return decodeYAMLConfig(data, config)
	}

	return decodeJSONConfig(data, config)
}

func decodeJSONConfig(data []byte, config *fileConfig) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(config); err != nil {
		return err
	}
	var extraValue json.RawMessage
	switch err := decoder.Decode(&extraValue); {
	case errors.Is(err, io.EOF):
	case err != nil:
		return err
	default:
		return errors.New("multiple JSON values are not allowed")
	}
	return nil
}

func decodeYAMLConfig(data []byte, config *fileConfig) error {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(config); err != nil {
		return err
	}

	var extra yaml.Node
	switch err := decoder.Decode(&extra); {
	case errors.Is(err, io.EOF):
		return nil
	case err != nil:
		return err
	default:
		return errors.New("multiple YAML documents are not allowed")
	}
}

func applyFileConfig(path string, parsedConfig fileConfig) (model.AuditConfig, error) {
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

	if parsedConfig.Rules != nil {
		if err := applyRulesSection(&config, *parsedConfig.Rules); err != nil {
			return model.AuditConfig{}, err
		}
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
		config.Profile.Paths.AppScanRoots = cloneStrings(laravelConfig.ScanRoots)
	}
}

func applyServicesSection(config *model.AuditConfig, servicesConfig fileServicesConfig) {
	if servicesConfig.UseDefaultPaths != nil {
		config.Profile.Paths.UseDefaultPatterns = *servicesConfig.UseDefaultPaths
	}

	applyServicePathConfig(&config.Profile.Switches.DiscoverNginx, &config.Profile.Paths.NginxConfigPatterns, servicesConfig.Nginx)
	applyServicePathConfig(&config.Profile.Switches.DiscoverPHPFPM, &config.Profile.Paths.PHPFPMPoolPatterns, servicesConfig.PHPFPM)
	applyServicePathConfig(&config.Profile.Switches.DiscoverMySQL, &config.Profile.Paths.MySQLConfigPatterns, servicesConfig.MySQL)
	applyServicePathConfig(&config.Profile.Switches.DiscoverSupervisor, &config.Profile.Paths.SupervisorConfigPatterns, servicesConfig.Supervisor)
	applyServicePathConfig(&config.Profile.Switches.DiscoverSystemd, &config.Profile.Paths.SystemdUnitPatterns, servicesConfig.Systemd)
	applyServiceCommandConfig(&config.Profile.Commands, servicesConfig)
}

func applyServicePathConfig(enabled *bool, paths *[]string, serviceConfig *fileServicePaths) {
	if serviceConfig == nil {
		return
	}
	if serviceConfig.Enabled != nil {
		*enabled = *serviceConfig.Enabled
	}
	if serviceConfig.Paths != nil {
		*paths = cloneStrings(serviceConfig.Paths)
	}
}

func applyServiceCommandConfig(commands *model.DiscoveryCommands, servicesConfig fileServicesConfig) {
	commands.NginxBinary = trimmedServiceBinary(servicesConfig.Nginx)
	commands.PHPFPMBinaries = serviceBinaryList(servicesConfig.PHPFPM)
	commands.SupervisorBinary = trimmedServiceBinary(servicesConfig.Supervisor)
}

func trimmedServiceBinary(serviceConfig *fileServicePaths) string {
	if serviceConfig == nil || serviceConfig.Binary == nil {
		return ""
	}

	return strings.TrimSpace(*serviceConfig.Binary)
}

func serviceBinaryList(serviceConfig *fileServicePaths) []string {
	if serviceConfig == nil {
		return nil
	}
	if serviceConfig.Binaries != nil {
		return cloneStrings(serviceConfig.Binaries)
	}
	if serviceConfig.Binary == nil {
		return nil
	}

	return []string{strings.TrimSpace(*serviceConfig.Binary)}
}

func applyRulesSection(config *model.AuditConfig, rulesConfig fileRulesConfig) error {
	config.Rules.Enable = cloneStrings(rulesConfig.Enable)
	config.Rules.Disable = cloneStrings(rulesConfig.Disable)
	config.Rules.CustomDirs = cloneStrings(rulesConfig.CustomDirs)

	if len(rulesConfig.Override) == 0 {
		config.Rules.Override = nil
		return nil
	}

	config.Rules.Override = make(map[string]model.RuleOverride, len(rulesConfig.Override))
	for ruleID, override := range rulesConfig.Override {
		parsedOverride := model.RuleOverride{Enabled: override.Enabled}

		if override.Severity != nil {
			parsedOverride.Severity = model.Severity(strings.ToLower(strings.TrimSpace(*override.Severity)))
			if !parsedOverride.Severity.Valid() {
				return fmt.Errorf("rules.override.%s.severity %q is invalid", ruleID, *override.Severity)
			}
		}

		if override.Confidence != nil {
			parsedOverride.Confidence = model.Confidence(strings.ToLower(strings.TrimSpace(*override.Confidence)))
			if !parsedOverride.Confidence.Valid() {
				return fmt.Errorf("rules.override.%s.confidence %q is invalid", ruleID, *override.Confidence)
			}
		}

		config.Rules.Override[strings.TrimSpace(ruleID)] = parsedOverride
	}

	return nil
}

// applyOutputFields applies common output-related config fields.
func applyOutputFields(config *model.AuditConfig, format *string, jsonPath *string, mdPath *string, verbosity *string, interactive *bool, color *string, screenReader *bool) {
	if format != nil {
		config.Format = model.NormalizeOutputFormat(*format)
	}
	if jsonPath != nil {
		config.ReportJSONPath = strings.TrimSpace(*jsonPath)
	}
	if mdPath != nil {
		config.ReportMarkdownPath = strings.TrimSpace(*mdPath)
	}
	if verbosity != nil {
		config.Verbosity = model.Verbosity(strings.ToLower(strings.TrimSpace(*verbosity)))
	}
	if interactive != nil {
		config.Interactive = *interactive
	}
	if color != nil {
		config.ColorMode = model.ColorMode(strings.ToLower(strings.TrimSpace(*color)))
	}
	if screenReader != nil {
		config.ScreenReader = *screenReader
	}
}

// applyAdvancedFields applies common advanced config fields, returning an error for invalid durations.
func applyAdvancedFields(config *model.AuditConfig, sectionName string, timeout *string, maxOutput *int, workers *int) error {
	if timeout != nil {
		commandTimeout, err := time.ParseDuration(strings.TrimSpace(*timeout))
		if err != nil {
			return fmt.Errorf("parse config %s.command_timeout: %w", sectionName, err)
		}
		config.CommandTimeout = commandTimeout
	}
	if maxOutput != nil {
		config.MaxOutputBytes = *maxOutput
	}
	if workers != nil {
		config.WorkerLimit = *workers
	}
	return nil
}

func applyOutputSection(config *model.AuditConfig, outputConfig fileOutputConfig) {
	applyOutputFields(config, outputConfig.Format, outputConfig.ReportJSONPath, outputConfig.ReportMarkdownPath, outputConfig.Verbosity, outputConfig.Interactive, outputConfig.Color, outputConfig.ScreenReader)
}

func applyAdvancedSection(config *model.AuditConfig, advancedConfig fileAdvancedConfig) error {
	return applyAdvancedFields(config, "advanced", advancedConfig.CommandTimeout, advancedConfig.MaxOutputBytes, advancedConfig.WorkerLimit)
}

func applyAuditSection(config *model.AuditConfig, auditConfig fileAuditConfig) error {
	applyOutputFields(config, auditConfig.Format, auditConfig.ReportJSONPath, auditConfig.ReportMarkdownPath, auditConfig.Verbosity, auditConfig.Interactive, auditConfig.Color, auditConfig.ScreenReader)
	if auditConfig.DebugLogPath != nil {
		config.DebugLogPath = strings.TrimSpace(*auditConfig.DebugLogPath)
	}

	if auditConfig.Scope != nil {
		config.Scope = model.ScanScope(strings.ToLower(strings.TrimSpace(*auditConfig.Scope)))
	}
	if auditConfig.AppPath != nil {
		config.AppPath = strings.TrimSpace(*auditConfig.AppPath)
	}
	if auditConfig.ScanRoots != nil {
		config.ScanRoots = cloneStrings(auditConfig.ScanRoots)
	}
	if auditConfig.VulnCheck != nil {
		config.VulnCheck = *auditConfig.VulnCheck
	}

	return applyAdvancedFields(config, "audit", auditConfig.CommandTimeout, auditConfig.MaxOutputBytes, auditConfig.WorkerLimit)
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
		config.Profile.Paths.AppScanRoots = cloneStrings(pathsConfig.AppScanRoots)
	}
	if pathsConfig.NginxConfigPatterns != nil {
		config.Profile.Paths.NginxConfigPatterns = cloneStrings(pathsConfig.NginxConfigPatterns)
	}
	if pathsConfig.PHPFPMPoolPatterns != nil {
		config.Profile.Paths.PHPFPMPoolPatterns = cloneStrings(pathsConfig.PHPFPMPoolPatterns)
	}
	if pathsConfig.MySQLConfigPatterns != nil {
		config.Profile.Paths.MySQLConfigPatterns = cloneStrings(pathsConfig.MySQLConfigPatterns)
	}
	if pathsConfig.SupervisorConfigPatterns != nil {
		config.Profile.Paths.SupervisorConfigPatterns = cloneStrings(pathsConfig.SupervisorConfigPatterns)
	}
	if pathsConfig.SystemdUnitPatterns != nil {
		config.Profile.Paths.SystemdUnitPatterns = cloneStrings(pathsConfig.SystemdUnitPatterns)
	}
}

func applySwitchesSection(config *model.AuditConfig, switchesConfig fileSwitchesConfig) {
	if switchesConfig.DiscoverNginx != nil {
		config.Profile.Switches.DiscoverNginx = *switchesConfig.DiscoverNginx
	}
	if switchesConfig.DiscoverPHPFPM != nil {
		config.Profile.Switches.DiscoverPHPFPM = *switchesConfig.DiscoverPHPFPM
	}
	if switchesConfig.DiscoverMySQL != nil {
		config.Profile.Switches.DiscoverMySQL = *switchesConfig.DiscoverMySQL
	}
	if switchesConfig.DiscoverSupervisor != nil {
		config.Profile.Switches.DiscoverSupervisor = *switchesConfig.DiscoverSupervisor
	}
	if switchesConfig.DiscoverSystemd != nil {
		config.Profile.Switches.DiscoverSystemd = *switchesConfig.DiscoverSystemd
	}
}

func cloneStrings(values []string) []string {
	if values == nil {
		return nil
	}

	return append([]string{}, values...)
}
