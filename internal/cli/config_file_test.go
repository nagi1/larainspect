package cli

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nagi1/larainspect/internal/model"
)

func TestLoadAuditConfigFileParsesSimpleSections(t *testing.T) {
	t.Parallel()

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
    }
  },
  "output": {
    "format": "json",
    "verbosity": "quiet"
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

	if config.Profile.Name != "fedora-prod" || config.NormalizedOSFamily() != "rhel" {
		t.Fatalf("unexpected profile config: %+v", config.Profile)
	}

	if config.AppPath != "/srv/laravel/shop/current" {
		t.Fatalf("expected app path to be loaded, got %q", config.AppPath)
	}

	if config.Profile.Paths.UseDefaultPatterns || len(config.NormalizedNginxConfigPatterns()) != 1 {
		t.Fatalf("expected custom-only patterns, got %+v", config.Profile.Paths)
	}

	if config.ShouldDiscoverPHPFPM() {
		t.Fatalf("expected discover_php_fpm=false to be respected")
	}
}

func TestLoadAuditConfigFileSupportsLegacySections(t *testing.T) {
	t.Parallel()

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

func TestResolveAuditConfigFilePathSupportsExplicitAndMissingFiles(t *testing.T) {
	t.Parallel()

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

func TestLoadAuditConfigFileRejectsUnknownKeys(t *testing.T) {
	t.Parallel()

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

func TestLoadAuditConfigFileAppliesLegacyPathAndSwitchSections(t *testing.T) {
	t.Parallel()

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
	t.Parallel()

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
	t.Parallel()

	config := model.DefaultAuditConfig()
	format := "json"
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
		Format:         &format,
		Verbosity:      &verbosity,
		Scope:          &scope,
		AppPath:        &appPath,
		ScanRoots:      []string{"/srv/apps", "/opt/apps"},
		Interactive:    &interactive,
		Color:          &color,
		ScreenReader:   &screenReader,
		CommandTimeout: &commandTimeout,
		MaxOutputBytes: &maxOutputBytes,
		WorkerLimit:    &workerLimit,
	})
	if err != nil {
		t.Fatalf("applyAuditSection() error = %v", err)
	}

	if config.Format != model.OutputFormatJSON {
		t.Fatalf("expected JSON output format, got %q", config.Format)
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
	t.Parallel()

	config := model.DefaultAuditConfig()
	useDefaultPatterns := false
	discoverNginx := false
	discoverPHPFPM := false
	discoverSupervisor := false
	discoverSystemd := false

	applyPathsSection(&config, filePathsConfig{
		UseDefaultPatterns:       &useDefaultPatterns,
		AppScanRoots:             []string{"/srv/apps", "/opt/apps"},
		NginxConfigPatterns:      []string{"/etc/nginx/custom/*.conf"},
		PHPFPMPoolPatterns:       []string{"/etc/php/custom/*.conf"},
		SupervisorConfigPatterns: []string{"/etc/supervisor/custom/*.conf"},
		SystemdUnitPatterns:      []string{"/etc/systemd/custom/*.service"},
	})
	applySwitchesSection(&config, fileSwitchesConfig{
		DiscoverNginx:      &discoverNginx,
		DiscoverPHPFPM:     &discoverPHPFPM,
		DiscoverSupervisor: &discoverSupervisor,
		DiscoverSystemd:    &discoverSystemd,
	})

	if config.Profile.Paths.UseDefaultPatterns {
		t.Fatal("expected default patterns to be disabled")
	}
	if len(config.Profile.Paths.AppScanRoots) != 2 || len(config.Profile.Paths.NginxConfigPatterns) != 1 {
		t.Fatalf("unexpected path overrides: %+v", config.Profile.Paths)
	}
	if len(config.Profile.Paths.PHPFPMPoolPatterns) != 1 || len(config.Profile.Paths.SupervisorConfigPatterns) != 1 || len(config.Profile.Paths.SystemdUnitPatterns) != 1 {
		t.Fatalf("unexpected service path overrides: %+v", config.Profile.Paths)
	}
	if config.ShouldDiscoverNginx() || config.ShouldDiscoverPHPFPM() || config.ShouldDiscoverSupervisor() || config.ShouldDiscoverSystemd() {
		t.Fatalf("expected discovery switches to be disabled: %+v", config.Profile.Switches)
	}
}

func writeConfigFileForTest(t *testing.T, path string, contents string) {
	t.Helper()

	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", path, err)
	}
}
