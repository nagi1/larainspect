package cli

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nagi1/larainspect/internal/model"
)

func TestLoadAuditConfigFileParsesSimpleSections(t *testing.T) {

	configPath := filepath.Join(t.TempDir(), "larainspect.json")
	writeConfigFileForTest(t, configPath, `{
  "version": 1,
  "server": {
    "name": "fedora-prod",
    "os": "fedora"
  },
  "laravel": {
    "scope": "host",
    "app_path": "/srv/laravel/shop/current",
    "scan_roots": ["/opt/apps"]
  },
  "services": {
    "use_default_paths": false,
    "nginx": {
      "enabled": true,
      "paths": ["/custom/nginx/*.conf"]
    },
    "php_fpm": {
      "enabled": false,
      "paths": ["/custom/php-fpm/*.conf"]
		},
		"mysql": {
			"enabled": true,
			"paths": ["/custom/mysql/*.cnf"]
    }
  },
  "output": {
    "format": "json",
    "verbosity": "quiet",
    "report_json_path": "/tmp/larainspect-report.json",
    "report_markdown_path": "/tmp/larainspect-report.md"
  },
  "advanced": {
    "command_timeout": "5s"
  }
}`)

	config, err := loadAuditConfigFile(configPath)
	if err != nil {
		t.Fatalf("loadAuditConfigFile() error = %v", err)
	}

	if config.ConfigPath != configPath {
		t.Fatalf("expected ConfigPath %q, got %q", configPath, config.ConfigPath)
	}
	if config.Format != model.OutputFormatJSON || config.Scope != model.ScanScopeHost {
		t.Fatalf("unexpected parsed audit config: %+v", config)
	}
	if config.ReportJSONPath != "/tmp/larainspect-report.json" {
		t.Fatalf("expected report json path, got %q", config.ReportJSONPath)
	}
	if config.ReportMarkdownPath != "/tmp/larainspect-report.md" {
		t.Fatalf("expected report markdown path, got %q", config.ReportMarkdownPath)
	}
	if config.Profile.Name != "fedora-prod" || config.NormalizedOSFamily() != "rhel" {
		t.Fatalf("unexpected profile config: %+v", config.Profile)
	}
	if config.AppPath != "/srv/laravel/shop/current" {
		t.Fatalf("expected app path to be loaded, got %q", config.AppPath)
	}
	if config.Profile.Paths.UseDefaultPatterns || len(config.NormalizedNginxConfigPatterns()) != 1 {
		t.Fatalf("expected custom-only patterns, got %+v", config.Profile.Paths)
	}
	if got := config.NormalizedMySQLConfigPatterns(); len(got) != 1 || got[0] != "/custom/mysql/*.cnf" {
		t.Fatalf("expected custom mysql patterns, got %+v", got)
	}
	if config.ShouldDiscoverPHPFPM() {
		t.Fatalf("expected discover_php_fpm=false to be respected")
	}
}

func TestLoadAuditConfigFileSupportsLegacySections(t *testing.T) {

	configPath := filepath.Join(t.TempDir(), "larainspect.json")
	writeConfigFileForTest(t, configPath, `{
  "version": 1,
  "audit": {
    "format": "json"
  },
  "profile": {
    "os_family": "fedora"
  },
  "paths": {
    "use_default_patterns": false,
    "nginx_config_patterns": ["/legacy/nginx/*.conf"]
  },
  "switches": {
    "discover_php_fpm": false
  }
}`)

	config, err := loadAuditConfigFile(configPath)
	if err != nil {
		t.Fatalf("loadAuditConfigFile() error = %v", err)
	}

	if config.Format != model.OutputFormatJSON || config.NormalizedOSFamily() != "rhel" {
		t.Fatalf("unexpected legacy config result: %+v", config)
	}
	if config.ShouldDiscoverPHPFPM() {
		t.Fatal("expected legacy discover_php_fpm=false to be respected")
	}
}

func TestLoadAuditConfigFileParsesRulesSection(t *testing.T) {

	configPath := filepath.Join(t.TempDir(), "larainspect.json")
	writeConfigFileForTest(t, configPath, `{
  "version": 1,
  "rules": {
    "enable": ["laravel.inject.eval"],
    "disable": ["laravel.debug.dd_call"],
    "custom_dirs": ["/tmp/team-rules"],
    "override": {
      "laravel.inject.eval": {
        "severity": "low",
        "confidence": "probable",
        "enabled": true
      }
    }
  }
}`)

	config, err := loadAuditConfigFile(configPath)
	if err != nil {
		t.Fatalf("loadAuditConfigFile() error = %v", err)
	}

	if len(config.Rules.Enable) != 1 || config.Rules.Enable[0] != "laravel.inject.eval" {
		t.Fatalf("unexpected rules.enable %+v", config.Rules.Enable)
	}
	if len(config.Rules.Disable) != 1 || config.Rules.Disable[0] != "laravel.debug.dd_call" {
		t.Fatalf("unexpected rules.disable %+v", config.Rules.Disable)
	}
	if len(config.Rules.CustomDirs) != 1 || config.Rules.CustomDirs[0] != "/tmp/team-rules" {
		t.Fatalf("unexpected rules.custom_dirs %+v", config.Rules.CustomDirs)
	}

	override, found := config.Rules.Override["laravel.inject.eval"]
	if !found {
		t.Fatal("expected rules.override entry")
	}
	if override.Severity != model.SeverityLow || override.Confidence != model.ConfidenceProbable {
		t.Fatalf("unexpected rules.override %+v", override)
	}
	if override.Enabled == nil || !*override.Enabled {
		t.Fatalf("expected rules.override.enabled=true, got %+v", override.Enabled)
	}
}

func TestLoadAuditConfigFileRejectsInvalidRulesOverride(t *testing.T) {

	configPath := filepath.Join(t.TempDir(), "larainspect.json")
	writeConfigFileForTest(t, configPath, `{
  "version": 1,
  "rules": {
    "override": {
      "laravel.inject.eval": {
        "severity": "severe"
      }
    }
  }
}`)

	if _, err := loadAuditConfigFile(configPath); err == nil {
		t.Fatal("expected invalid rules.override.severity error")
	}
}

func TestLoadAuditConfigFileRejectsInvalidRulesOverrideConfidence(t *testing.T) {

	configPath := filepath.Join(t.TempDir(), "larainspect.json")
	writeConfigFileForTest(t, configPath, `{
  "version": 1,
  "rules": {
    "override": {
      "laravel.inject.eval": {
        "confidence": "certain"
      }
    }
  }
}`)

	if _, err := loadAuditConfigFile(configPath); err == nil {
		t.Fatal("expected invalid rules.override.confidence error")
	}
}

func TestApplyRulesSectionAllowsEmptyOverrides(t *testing.T) {

	config := model.DefaultAuditConfig()
	if err := applyRulesSection(&config, fileRulesConfig{
		Enable:     []string{"one"},
		Disable:    []string{"two"},
		CustomDirs: []string{"/tmp/rules"},
	}); err != nil {
		t.Fatalf("applyRulesSection() error = %v", err)
	}

	if config.Rules.Override != nil {
		t.Fatalf("expected nil override map, got %+v", config.Rules.Override)
	}
	if len(config.Rules.Enable) != 1 || len(config.Rules.Disable) != 1 || len(config.Rules.CustomDirs) != 1 {
		t.Fatalf("unexpected rules config %+v", config.Rules)
	}
}

func TestResolveAuditConfigFilePathSupportsExplicitAndMissingFiles(t *testing.T) {

	configPath := filepath.Join(t.TempDir(), "larainspect.json")
	writeConfigFileForTest(t, configPath, `{}`)

	resolvedPath, err := resolveAuditConfigFilePath(configPath)
	if err != nil {
		t.Fatalf("resolveAuditConfigFilePath() explicit error = %v", err)
	}
	if resolvedPath != configPath {
		t.Fatalf("expected resolved path %q, got %q", configPath, resolvedPath)
	}
	if _, err := resolveAuditConfigFilePath(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("expected explicit missing config error")
	}
}

func TestResolveAuditConfigFilePathReturnsEmptyWithoutConfig(t *testing.T) {
	workingDirectory := t.TempDir()
	originalWorkingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd() error = %v", err)
	}
	if err := os.Chdir(workingDirectory); err != nil {
		t.Fatalf("Chdir() error = %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(originalWorkingDirectory)
	})

	resolvedPath, err := resolveAuditConfigFilePath("")
	if err != nil {
		t.Fatalf("resolveAuditConfigFilePath() error = %v", err)
	}
	if resolvedPath != "" {
		t.Fatalf("expected empty path, got %q", resolvedPath)
	}
}

func TestLoadAuditConfigFileRejectsUnknownKeys(t *testing.T) {

	configPath := filepath.Join(t.TempDir(), "larainspect.json")
	writeConfigFileForTest(t, configPath, `{
  "version": 1,
  "audit": {
    "format": "json",
    "format_typo": "terminal"
  }
}`)

	if _, err := loadAuditConfigFile(configPath); err == nil {
		t.Fatal("expected unknown config key error")
	}
}

func TestLoadAuditConfigFileRejectsUnsupportedVersion(t *testing.T) {

	configPath := filepath.Join(t.TempDir(), "larainspect.json")
	writeConfigFileForTest(t, configPath, `{
  "version": 2
}`)

	if _, err := loadAuditConfigFile(configPath); err == nil {
		t.Fatal("expected unsupported version error")
	}
}

func TestLoadAuditConfigFileRejectsMultipleJSONValues(t *testing.T) {

	configPath := filepath.Join(t.TempDir(), "larainspect.json")
	writeConfigFileForTest(t, configPath, "{}\n{}")

	if _, err := loadAuditConfigFile(configPath); err == nil {
		t.Fatal("expected multiple JSON values error")
	}
}

func TestLoadAuditConfigFileAppliesLegacyPathAndSwitchSections(t *testing.T) {

	configPath := filepath.Join(t.TempDir(), "larainspect.json")
	writeConfigFileForTest(t, configPath, `{
  "version": 1,
  "profile": {
    "name": "prod"
  },
  "paths": {
    "use_default_patterns": false,
    "supervisor_config_patterns": ["/srv/supervisor/*.conf"],
    "systemd_unit_patterns": ["/srv/systemd/*.service"]
  },
  "switches": {
    "discover_supervisor": false,
    "discover_systemd": false
  },
  "output": {
    "interactive": true,
    "color": "never",
    "screen_reader": true
  },
  "advanced": {
    "max_output_bytes": 2048,
    "worker_limit": 3
  }
}`)

	config, err := loadAuditConfigFile(configPath)
	if err != nil {
		t.Fatalf("loadAuditConfigFile() error = %v", err)
	}

	if config.Profile.Name != "prod" || config.ShouldDiscoverSupervisor() || config.ShouldDiscoverSystemd() {
		t.Fatalf("unexpected profile switches: %+v", config)
	}
	if config.ColorMode != model.ColorModeNever || !config.Interactive || !config.ScreenReader {
		t.Fatalf("unexpected output config: %+v", config)
	}
	if config.MaxOutputBytes != 2048 || config.WorkerLimit != 3 {
		t.Fatalf("unexpected advanced config: %+v", config)
	}
}

func TestLoadAuditConfigFileRejectsInvalidAdvancedTimeout(t *testing.T) {

	configPath := filepath.Join(t.TempDir(), "larainspect.json")
	writeConfigFileForTest(t, configPath, `{
  "version": 1,
  "advanced": {
    "command_timeout": "not-a-duration"
  }
}`)

	if _, err := loadAuditConfigFile(configPath); err == nil {
		t.Fatal("expected invalid timeout error")
	}
}

func TestApplyAuditSectionAppliesAllSupportedFields(t *testing.T) {

	config := model.DefaultAuditConfig()
	format := "json"
	reportJSONPath := "/tmp/report.json"
	reportMarkdownPath := "/tmp/report.md"
	verbosity := "verbose"
	scope := "host"
	appPath := " /srv/www/shop/current "
	interactive := true
	color := "never"
	screenReader := true
	commandTimeout := "12s"
	maxOutputBytes := 8192
	workerLimit := 6

	err := applyAuditSection(&config, fileAuditConfig{
		Format:             &format,
		ReportJSONPath:     &reportJSONPath,
		ReportMarkdownPath: &reportMarkdownPath,
		Verbosity:          &verbosity,
		Scope:              &scope,
		AppPath:            &appPath,
		ScanRoots:          []string{"/srv/apps", "/opt/apps"},
		Interactive:        &interactive,
		Color:              &color,
		ScreenReader:       &screenReader,
		CommandTimeout:     &commandTimeout,
		MaxOutputBytes:     &maxOutputBytes,
		WorkerLimit:        &workerLimit,
	})
	if err != nil {
		t.Fatalf("applyAuditSection() error = %v", err)
	}

	if config.Format != model.OutputFormatJSON {
		t.Fatalf("expected JSON output format, got %q", config.Format)
	}
	if config.ReportJSONPath != reportJSONPath {
		t.Fatalf("expected report json path, got %q", config.ReportJSONPath)
	}
	if config.ReportMarkdownPath != reportMarkdownPath {
		t.Fatalf("expected report markdown path, got %q", config.ReportMarkdownPath)
	}
	if config.Verbosity != model.VerbosityVerbose {
		t.Fatalf("expected verbose verbosity, got %q", config.Verbosity)
	}
	if config.Scope != model.ScanScopeHost {
		t.Fatalf("expected host scope, got %q", config.Scope)
	}
	if config.AppPath != "/srv/www/shop/current" {
		t.Fatalf("expected trimmed app path, got %q", config.AppPath)
	}
	if len(config.ScanRoots) != 2 || config.ScanRoots[0] != "/srv/apps" || config.ScanRoots[1] != "/opt/apps" {
		t.Fatalf("unexpected scan roots: %+v", config.ScanRoots)
	}
	if !config.Interactive || config.ColorMode != model.ColorModeNever || !config.ScreenReader {
		t.Fatalf("unexpected interactive/color/screen-reader values: %+v", config)
	}
	if config.CommandTimeout != 12*time.Second {
		t.Fatalf("expected 12s timeout, got %s", config.CommandTimeout)
	}
	if config.MaxOutputBytes != 8192 || config.WorkerLimit != 6 {
		t.Fatalf("unexpected max output bytes or worker limit: %+v", config)
	}
}

func TestApplyPathsAndSwitchesSectionsApplyAllOverrides(t *testing.T) {

	config := model.DefaultAuditConfig()
	useDefaultPatterns := false
	discoverNginx := false
	discoverPHPFPM := false
	discoverMySQL := false
	discoverSupervisor := false
	discoverSystemd := false

	applyPathsSection(&config, filePathsConfig{
		UseDefaultPatterns:       &useDefaultPatterns,
		AppScanRoots:             []string{"/srv/apps", "/opt/apps"},
		NginxConfigPatterns:      []string{"/etc/nginx/custom/*.conf"},
		PHPFPMPoolPatterns:       []string{"/etc/php/custom/*.conf"},
		MySQLConfigPatterns:      []string{"/etc/mysql/custom/*.cnf"},
		SupervisorConfigPatterns: []string{"/etc/supervisor/custom/*.conf"},
		SystemdUnitPatterns:      []string{"/etc/systemd/custom/*.service"},
	})
	applySwitchesSection(&config, fileSwitchesConfig{
		DiscoverNginx:      &discoverNginx,
		DiscoverPHPFPM:     &discoverPHPFPM,
		DiscoverMySQL:      &discoverMySQL,
		DiscoverSupervisor: &discoverSupervisor,
		DiscoverSystemd:    &discoverSystemd,
	})

	if config.Profile.Paths.UseDefaultPatterns {
		t.Fatal("expected default patterns to be disabled")
	}
	if len(config.Profile.Paths.AppScanRoots) != 2 || len(config.Profile.Paths.NginxConfigPatterns) != 1 {
		t.Fatalf("unexpected path overrides: %+v", config.Profile.Paths)
	}
	if len(config.Profile.Paths.PHPFPMPoolPatterns) != 1 || len(config.Profile.Paths.MySQLConfigPatterns) != 1 || len(config.Profile.Paths.SupervisorConfigPatterns) != 1 || len(config.Profile.Paths.SystemdUnitPatterns) != 1 {
		t.Fatalf("unexpected service path overrides: %+v", config.Profile.Paths)
	}
	if config.ShouldDiscoverNginx() || config.ShouldDiscoverPHPFPM() || config.ShouldDiscoverMySQL() || config.ShouldDiscoverSupervisor() || config.ShouldDiscoverSystemd() {
		t.Fatalf("expected discovery switches to be disabled: %+v", config.Profile.Switches)
	}
}

func writeConfigFileForTest(t *testing.T, path string, contents string) {
	t.Helper()

	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", path, err)
	}
}
