package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nagi1/larainspect/internal/model"
)

func TestLoadAuditConfigFileYAMLParsesSimpleSections(t *testing.T) {

	configPath := filepath.Join(t.TempDir(), "larainspect.yaml")
	writeConfigFileForTest(t, configPath, strings.Join([]string{
		"version: 1",
		"server:",
		"  name: fedora-prod",
		"  os: fedora",
		"laravel:",
		"  scope: host",
		"  app_path: /srv/laravel/shop/current",
		"  scan_roots:",
		"    - /opt/apps",
		"services:",
		"  use_default_paths: false",
		"  nginx:",
		"    enabled: true",
		"    binary: /www/server/nginx/sbin/nginx",
		"    paths:",
		"      - /custom/nginx/*.conf",
		"  php_fpm:",
		"    enabled: false",
		"    binaries:",
		"      - /www/server/php/83/sbin/php-fpm",
		"      - /www/server/php/85/sbin/php-fpm",
		"    paths:",
		"      - /custom/php-fpm/*.conf",
		"  mysql:",
		"    enabled: true",
		"    paths:",
		"      - /custom/mysql/*.cnf",
		"output:",
		"  format: json",
		"  verbosity: quiet",
		"  report_json_path: /tmp/larainspect-report.json",
		"  report_markdown_path: /tmp/larainspect-report.md",
		"advanced:",
		"  command_timeout: 5s",
	}, "\n"))

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
	if config.NormalizedNginxBinary() != "/www/server/nginx/sbin/nginx" {
		t.Fatalf("expected nginx binary to be loaded, got %q", config.NormalizedNginxBinary())
	}
	if got := config.NormalizedPHPFPMBinaries(); len(got) != 2 || got[0] != "/www/server/php/83/sbin/php-fpm" || got[1] != "/www/server/php/85/sbin/php-fpm" {
		t.Fatalf("expected php-fpm binaries to be loaded, got %+v", got)
	}
	if got := config.NormalizedMySQLConfigPatterns(); len(got) != 1 || got[0] != "/custom/mysql/*.cnf" {
		t.Fatalf("expected mysql config paths to be loaded, got %+v", got)
	}
	if config.Profile.Paths.UseDefaultPatterns || len(config.NormalizedNginxConfigPatterns()) != 1 {
		t.Fatalf("expected custom-only patterns, got %+v", config.Profile.Paths)
	}
	if config.ShouldDiscoverPHPFPM() {
		t.Fatalf("expected discover_php_fpm=false to be respected")
	}
	if config.CommandTimeout != 5*time.Second {
		t.Fatalf("expected 5s timeout, got %s", config.CommandTimeout)
	}
}

func TestLoadAuditConfigFileYAMLSupportsLegacySections(t *testing.T) {

	configPath := filepath.Join(t.TempDir(), "larainspect.yaml")
	writeConfigFileForTest(t, configPath, `
version: 1
audit:
  format: json
profile:
  os_family: fedora
paths:
  use_default_patterns: false
  nginx_config_patterns:
    - "/legacy/nginx/*.conf"
switches:
  discover_php_fpm: false
`)

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

func TestLoadAuditConfigFileYAMLParsesRulesSection(t *testing.T) {

	configPath := filepath.Join(t.TempDir(), "larainspect.yaml")
	writeConfigFileForTest(t, configPath, `
version: 1
rules:
  enable:
    - laravel.inject.eval
  disable:
    - laravel.debug.dd_call
  custom_dirs:
    - /tmp/team-rules
  override:
    laravel.inject.eval:
      severity: low
      confidence: probable
      enabled: true
`)

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

func TestLoadAuditConfigFileYAMLRejectsUnknownKeys(t *testing.T) {

	configPath := filepath.Join(t.TempDir(), "larainspect.yaml")
	writeConfigFileForTest(t, configPath, `
version: 1
audit:
  format: json
  format_typo: terminal
`)

	if _, err := loadAuditConfigFile(configPath); err == nil {
		t.Fatal("expected unknown config key error")
	}
}

func TestLoadAuditConfigFileYAMLRejectsUnsupportedVersion(t *testing.T) {

	configPath := filepath.Join(t.TempDir(), "larainspect.yml")
	writeConfigFileForTest(t, configPath, `version: 2`)

	if _, err := loadAuditConfigFile(configPath); err == nil {
		t.Fatal("expected unsupported version error")
	}
}

func TestLoadAuditConfigFileYAMLRejectsMultipleDocuments(t *testing.T) {

	configPath := filepath.Join(t.TempDir(), "larainspect.yaml")
	writeConfigFileForTest(t, configPath, "version: 1\n---\nversion: 1\n")

	if _, err := loadAuditConfigFile(configPath); err == nil {
		t.Fatal("expected multiple YAML documents error")
	}
}

func TestLoadAuditConfigFileYAMLRejectsMalformedTrailingDocument(t *testing.T) {

	configPath := filepath.Join(t.TempDir(), "larainspect.yaml")
	writeConfigFileForTest(t, configPath, "version: 1\n---\noutput:\n  format: [\n")

	if _, err := loadAuditConfigFile(configPath); err == nil {
		t.Fatal("expected malformed trailing YAML document error")
	}
}

func TestLoadAuditConfigFileYAMLRejectsInvalidRulesOverride(t *testing.T) {

	configPath := filepath.Join(t.TempDir(), "larainspect.yaml")
	writeConfigFileForTest(t, configPath, `
version: 1
rules:
  override:
    laravel.inject.eval:
      severity: severe
`)

	if _, err := loadAuditConfigFile(configPath); err == nil {
		t.Fatal("expected invalid rules.override.severity error")
	}
}

func TestLoadAuditConfigFileYAMLRejectsInvalidTimeout(t *testing.T) {

	configPath := filepath.Join(t.TempDir(), "larainspect.yaml")
	writeConfigFileForTest(t, configPath, `
version: 1
advanced:
  command_timeout: not-a-duration
`)

	if _, err := loadAuditConfigFile(configPath); err == nil {
		t.Fatal("expected invalid timeout error")
	}
}

func TestLoadAuditConfigFileYMLExtension(t *testing.T) {

	configPath := filepath.Join(t.TempDir(), "config.yml")
	writeConfigFileForTest(t, configPath, `
version: 1
server:
  name: test-yml
`)

	config, err := loadAuditConfigFile(configPath)
	if err != nil {
		t.Fatalf("loadAuditConfigFile() error = %v", err)
	}

	if config.Profile.Name != "test-yml" {
		t.Fatalf("expected profile name %q, got %q", "test-yml", config.Profile.Name)
	}
}

func TestIsYAMLConfigFile(t *testing.T) {

	testCases := []struct {
		path string
		want bool
	}{
		{path: "larainspect.yaml", want: true},
		{path: "larainspect.yml", want: true},
		{path: ".larainspect.YAML", want: true},
		{path: ".larainspect.YML", want: true},
		{path: "larainspect.json", want: false},
		{path: "config", want: false},
		{path: "rules.toml", want: false},
	}

	for _, testCase := range testCases {
		if got := isYAMLConfigFile(testCase.path); got != testCase.want {
			t.Errorf("isYAMLConfigFile(%q) = %v, want %v", testCase.path, got, testCase.want)
		}
	}
}

func TestDefaultAuditConfigPathsYAMLFirst(t *testing.T) {

	paths := defaultAuditConfigPaths()
	if len(paths) < 4 {
		t.Fatalf("expected at least 4 default paths, got %d", len(paths))
	}
	if !isYAMLConfigFile(paths[0]) {
		t.Fatalf("expected first default path to be YAML, got %q", paths[0])
	}
}

func TestResolveAuditConfigFilePathPrefersYAML(t *testing.T) {
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

	writeConfigFileForTest(t, filepath.Join(workingDirectory, "larainspect.yaml"), "version: 1\n")
	writeConfigFileForTest(t, filepath.Join(workingDirectory, "larainspect.json"), "{}\n")

	resolvedPath, err := resolveAuditConfigFilePath("")
	if err != nil {
		t.Fatalf("resolveAuditConfigFilePath() error = %v", err)
	}
	if !isYAMLConfigFile(resolvedPath) {
		t.Fatalf("expected YAML to be preferred, got %q", resolvedPath)
	}
}

func TestDecodeJSONConfigRejectsMultipleValues(t *testing.T) {

	var config fileConfig
	if err := decodeJSONConfig([]byte("{}\n{}"), &config); err == nil {
		t.Fatal("expected error for multiple JSON values")
	}
}

func TestDecodeYAMLConfigRejectsMultipleDocuments(t *testing.T) {

	var config fileConfig
	if err := decodeYAMLConfig([]byte("version: 1\n---\nversion: 1\n"), &config); err == nil {
		t.Fatal("expected error for multiple YAML documents")
	}
}

func TestDecodeYAMLConfigRejectsUnknownFields(t *testing.T) {

	var config fileConfig
	if err := decodeYAMLConfig([]byte("version: 1\nbogus_key: true\n"), &config); err == nil {
		t.Fatal("expected error for unknown YAML key")
	}
}

func TestDecodeYAMLConfigRejectsMalformedTrailingDocument(t *testing.T) {

	var config fileConfig
	if err := decodeYAMLConfig([]byte("version: 1\n---\noutput:\n  format: [\n"), &config); err == nil {
		t.Fatal("expected error for malformed trailing YAML document")
	}
}

func TestLoadAuditConfigFileYAMLFullAllSections(t *testing.T) {

	configPath := filepath.Join(t.TempDir(), "larainspect.yaml")
	writeConfigFileForTest(t, configPath, strings.Join([]string{
		"version: 1",
		"server:",
		"  name: prod",
		"  os: ubuntu",
		"laravel:",
		"  scope: app",
		"  app_path: /var/www/app",
		"  scan_roots:",
		"    - /var/www",
		"services:",
		"  use_default_paths: true",
		"  nginx:",
		"    enabled: true",
		"    paths:",
		"      - /etc/nginx/*.conf",
		"  php_fpm:",
		"    enabled: true",
		"    paths:",
		"      - /etc/php/*.conf",
		"  mysql:",
		"    enabled: true",
		"    paths:",
		"      - /etc/mysql/*.cnf",
		"  supervisor:",
		"    enabled: false",
		"    paths: []",
		"  systemd:",
		"    enabled: false",
		"    paths: []",
		"output:",
		"  format: terminal",
		"  verbosity: verbose",
		"  interactive: true",
		"  color: never",
		"  screen_reader: true",
		"advanced:",
		"  command_timeout: 10s",
		"  max_output_bytes: 2048",
		"  worker_limit: 2",
		"rules:",
		"  enable:",
		"    - laravel.debug.dd_call",
		"  disable:",
		"    - laravel.inject.eval",
		"  custom_dirs:",
		"    - /tmp/rules",
		"  override:",
		"    laravel.debug.dd_call:",
		"      severity: medium",
	}, "\n"))

	config, err := loadAuditConfigFile(configPath)
	if err != nil {
		t.Fatalf("loadAuditConfigFile() error = %v", err)
	}

	if config.Profile.Name != "prod" || config.Profile.OSFamily != "ubuntu" {
		t.Fatalf("unexpected profile: %+v", config.Profile)
	}
	if config.Scope != model.ScanScopeApp || config.AppPath != "/var/www/app" {
		t.Fatalf("unexpected scope/app_path: scope=%q app_path=%q", config.Scope, config.AppPath)
	}
	if !config.Interactive || config.ColorMode != model.ColorModeNever || !config.ScreenReader {
		t.Fatalf("unexpected output: interactive=%v color=%q screen_reader=%v", config.Interactive, config.ColorMode, config.ScreenReader)
	}
	if config.Verbosity != model.VerbosityVerbose {
		t.Fatalf("expected verbose, got %q", config.Verbosity)
	}
	if config.CommandTimeout != 10*time.Second || config.MaxOutputBytes != 2048 || config.WorkerLimit != 2 {
		t.Fatalf("unexpected advanced config: timeout=%s max_output=%d workers=%d", config.CommandTimeout, config.MaxOutputBytes, config.WorkerLimit)
	}
	if len(config.Rules.Enable) != 1 || len(config.Rules.Disable) != 1 || len(config.Rules.CustomDirs) != 1 {
		t.Fatalf("unexpected rules: %+v", config.Rules)
	}

	override, found := config.Rules.Override["laravel.debug.dd_call"]
	if !found || override.Severity != model.SeverityMedium {
		t.Fatalf("unexpected rules.override: %+v", config.Rules.Override)
	}
	if config.ShouldDiscoverSupervisor() || config.ShouldDiscoverSystemd() {
		t.Fatalf("expected supervisor and systemd disabled")
	}
	got := config.NormalizedMySQLConfigPatterns()
	if len(got) < 2 {
		t.Fatalf("expected default and explicit mysql patterns, got %+v", got)
	}
	foundExplicitMySQLPattern := false
	for _, pattern := range got {
		if pattern == "/etc/mysql/*.cnf" {
			foundExplicitMySQLPattern = true
			break
		}
	}
	if !foundExplicitMySQLPattern {
		t.Fatalf("expected explicit mysql pattern, got %+v", got)
	}
}
