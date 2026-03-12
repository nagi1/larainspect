package cli

import (
	"os"
	"path/filepath"
	"testing"

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

func writeConfigFileForTest(t *testing.T, path string, contents string) {
	t.Helper()

	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", path, err)
	}
}
