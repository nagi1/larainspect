package discovery

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nagi1/larainspect/internal/model"
)

func TestParseNginxSitesParsesRelevantLaravelSignals(t *testing.T) {
	t.Parallel()

	sites, err := parseNginxSites("/etc/nginx/sites-enabled/shop.conf", `
server {
    server_name shop.test;
    root /var/www/shop/public;
    index index.php index.html;

    location = /index.php {
        fastcgi_pass unix:/run/php/shop.sock;
    }

    location ~ \.php$ {
        fastcgi_pass unix:/run/php/shop.sock;
    }

    location ~ /\.(?!well-known).* {
        deny all;
    }

    location ~* \.(env|sql|zip)$ {
        return 404;
    }

    location ~ ^/uploads/.*\.php$ {
        fastcgi_pass unix:/run/php/shop.sock;
    }
}
`)
	if err != nil {
		t.Fatalf("parseNginxSites() error = %v", err)
	}

	if len(sites) != 1 {
		t.Fatalf("expected 1 site, got %+v", sites)
	}

	site := sites[0]
	if !site.HasGenericPHPLocation || !site.HasFrontControllerOnly || !site.HiddenFilesDenied || !site.SensitiveFilesDenied || !site.UploadExecutionAllowed {
		t.Fatalf("expected parsed nginx protections and execution signals, got %+v", site)
	}

	if len(site.FastCGIPassTargets) != 1 || site.FastCGIPassTargets[0] != "unix:/run/php/shop.sock" {
		t.Fatalf("unexpected fastcgi_pass targets: %+v", site.FastCGIPassTargets)
	}
}

func TestParseNginxSitesRejectsUnbalancedConfig(t *testing.T) {
	t.Parallel()

	if _, err := parseNginxSites("/etc/nginx/nginx.conf", "server {"); err == nil {
		t.Fatal("expected nginx parse error for unbalanced braces")
	}
}

func TestParsePHPFPMPoolsParsesPoolDefinitions(t *testing.T) {
	t.Parallel()

	pools, err := parsePHPFPMPools("/etc/php/8.3/fpm/pool.d/www.conf", `
[www]
user = www-data
group = www-data
listen = /run/php/www.sock
listen.owner = www-data
listen.group = www-data
listen.mode = 0660
clear_env = no
`)
	if err != nil {
		t.Fatalf("parsePHPFPMPools() error = %v", err)
	}

	if len(pools) != 1 {
		t.Fatalf("expected 1 pool, got %+v", pools)
	}

	if pools[0].Listen != "/run/php/www.sock" || pools[0].ListenMode != "0660" || pools[0].ClearEnv != "no" {
		t.Fatalf("unexpected pool contents: %+v", pools[0])
	}
}

func TestParsePHPFPMPoolsRejectsEmptySectionName(t *testing.T) {
	t.Parallel()

	if _, err := parsePHPFPMPools("/etc/php/8.3/fpm/pool.d/www.conf", "[]\nlisten = /run/php/www.sock\n"); err == nil {
		t.Fatal("expected php-fpm parse error for empty section name")
	}
}

func TestSnapshotServiceDiscoversNginxAndPHPFPMConfigs(t *testing.T) {
	t.Parallel()

	configRoot := t.TempDir()
	nginxConfigPath := filepath.Join(configRoot, "nginx", "shop.conf")
	phpFPMConfigPath := filepath.Join(configRoot, "php-fpm", "shop.conf")

	if err := os.MkdirAll(filepath.Dir(nginxConfigPath), 0o755); err != nil {
		t.Fatalf("MkdirAll(nginx) error = %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(phpFPMConfigPath), 0o755); err != nil {
		t.Fatalf("MkdirAll(php-fpm) error = %v", err)
	}

	writeTestFile(t, nginxConfigPath, "server { root /var/www/shop/public; location ~ \\.php$ { fastcgi_pass unix:/run/php/shop.sock; } }")
	writeTestFile(t, phpFPMConfigPath, "[shop]\nuser = www-data\nlisten = /run/php/shop.sock\nlisten.mode = 0660\n")

	service := newTestSnapshotService()
	service.nginxPatterns = []string{nginxConfigPath}
	service.phpFPMPatterns = []string{phpFPMConfigPath}

	snapshot, unknowns, err := service.Discover(context.Background(), model.ExecutionContext{
		Config: model.AuditConfig{Scope: model.ScanScopeHost},
	})
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}

	if len(unknowns) != 0 {
		t.Fatalf("expected no unknowns, got %+v", unknowns)
	}

	if len(snapshot.NginxSites) != 1 || len(snapshot.PHPFPMPools) != 1 {
		t.Fatalf("expected discovered nginx and php-fpm configs, got %+v %+v", snapshot.NginxSites, snapshot.PHPFPMPools)
	}
}

func TestSnapshotServiceReportsConfigReadErrorsAsUnknowns(t *testing.T) {
	t.Parallel()

	service := newTestSnapshotService()
	service.nginxPatterns = []string{"/etc/nginx/nginx.conf"}
	service.statPath = func(path string) (fs.FileInfo, error) {
		return nil, fs.ErrPermission
	}
	service.readFile = func(path string) ([]byte, error) {
		return nil, fs.ErrPermission
	}

	_, unknowns, err := service.Discover(context.Background(), model.ExecutionContext{
		Config: model.AuditConfig{Scope: model.ScanScopeHost},
	})
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}

	if len(unknowns) != 1 {
		t.Fatalf("expected 1 unknown, got %+v", unknowns)
	}

	if unknowns[0].Error != model.ErrorKindPermissionDenied {
		t.Fatalf("expected permission denied unknown, got %+v", unknowns[0])
	}
}

func TestSnapshotServiceReportsConfigParseErrorsAsUnknowns(t *testing.T) {
	t.Parallel()

	configRoot := t.TempDir()
	nginxConfigPath := filepath.Join(configRoot, "nginx", "broken.conf")
	if err := os.MkdirAll(filepath.Dir(nginxConfigPath), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	writeTestFile(t, nginxConfigPath, "server {")

	service := newTestSnapshotService()
	service.nginxPatterns = []string{nginxConfigPath}

	_, unknowns, err := service.Discover(context.Background(), model.ExecutionContext{
		Config: model.AuditConfig{Scope: model.ScanScopeHost},
	})
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}

	if len(unknowns) != 1 {
		t.Fatalf("expected 1 unknown, got %+v", unknowns)
	}

	if unknowns[0].Error != model.ErrorKindParseFailure {
		t.Fatalf("expected parse failure unknown, got %+v", unknowns[0])
	}
}

func TestExpandConfigPatternIgnoresMissingDirectFiles(t *testing.T) {
	t.Parallel()

	service := newTestSnapshotService()
	matches, err := service.expandConfigPattern(filepath.Join(t.TempDir(), "missing.conf"))
	if err != nil {
		t.Fatalf("expandConfigPattern() error = %v", err)
	}

	if len(matches) != 0 {
		t.Fatalf("expected no matches, got %+v", matches)
	}
}

func TestExpandConfigPatternPropagatesGlobErrors(t *testing.T) {
	t.Parallel()

	service := newTestSnapshotService()
	service.globPaths = func(pattern string) ([]string, error) {
		return nil, errors.New("bad glob")
	}

	if _, err := service.expandConfigPattern("*.conf"); err == nil {
		t.Fatal("expected glob error")
	}
}

func TestEnvironmentAndPathHelpersCoverEdgeCases(t *testing.T) {
	t.Parallel()

	if got := normalizeEnvironmentValue(`"quoted" # trailing comment`); got != "quoted" {
		t.Fatalf("normalizeEnvironmentValue() = %q", got)
	}
	if got := normalizeEnvironmentValue(`'single-quoted'`); got != "single-quoted" {
		t.Fatalf("normalizeEnvironmentValue() = %q", got)
	}

	if got := stripPHPFPMComments("; comment only\n# another\nlisten = /run/php.sock\n"); got == "" || !containsLine(got, "listen = /run/php.sock") {
		t.Fatalf("stripPHPFPMComments() removed directive unexpectedly: %q", got)
	}

	if classifyFilesystemError(errors.New("boom")) != model.ErrorKindNotEnoughData {
		t.Fatal("expected default filesystem error classification")
	}
}

func TestInspectPathRecordHandlesSymlinksAndPermissionErrors(t *testing.T) {
	t.Parallel()

	rootPath := t.TempDir()
	targetPath := filepath.Join(rootPath, "shared-env")
	symlinkPath := filepath.Join(rootPath, ".env")
	writeTestFile(t, targetPath, "APP_KEY=base64:dGVzdA==\n")
	if err := os.Symlink(targetPath, symlinkPath); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}

	service := newTestSnapshotService()
	pathRecord, unknown := service.inspectPathRecord(rootPath, ".env")
	if unknown != nil {
		t.Fatalf("inspectPathRecord() unexpected unknown = %+v", unknown)
	}
	if !pathRecord.IsSymlink() || pathRecord.ResolvedPath == "" {
		t.Fatalf("expected symlink metadata, got %+v", pathRecord)
	}

	service.lstatPath = func(path string) (fs.FileInfo, error) {
		return nil, fs.ErrPermission
	}
	if _, unknown := service.inspectPathRecord(rootPath, ".env"); unknown == nil || unknown.Error != model.ErrorKindPermissionDenied {
		t.Fatalf("expected permission-denied unknown, got %+v", unknown)
	}
}

func TestCollectArtifactRecordsSkipsLargeDependencyTrees(t *testing.T) {
	t.Parallel()

	rootPath := t.TempDir()
	if err := os.MkdirAll(filepath.Join(rootPath, "vendor/deep"), 0o755); err != nil {
		t.Fatalf("MkdirAll(vendor) error = %v", err)
	}
	if err := os.MkdirAll(filepath.Join(rootPath, "public/uploads"), 0o755); err != nil {
		t.Fatalf("MkdirAll(public/uploads) error = %v", err)
	}
	writeTestFile(t, filepath.Join(rootPath, "vendor/deep/cache.sql"), "ignore me\n")
	writeTestFile(t, filepath.Join(rootPath, "public/uploads/shell.php"), "<?php echo 1;\n")

	service := newTestSnapshotService()
	artifacts, unknowns := service.collectArtifactRecords(context.Background(), rootPath)
	if len(unknowns) != 0 {
		t.Fatalf("expected no unknowns, got %+v", unknowns)
	}
	if len(artifacts) != 1 || artifacts[0].Kind != model.ArtifactKindPublicPHPFile {
		t.Fatalf("expected only public upload php artifact, got %+v", artifacts)
	}
}

func containsLine(contents string, targetLine string) bool {
	for _, line := range strings.Split(contents, "\n") {
		if strings.TrimSpace(line) == targetLine {
			return true
		}
	}

	return false
}
