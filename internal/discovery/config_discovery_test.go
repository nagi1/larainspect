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

func TestParseNginxSitesRecognizesAlternateExecutablePHPExtensions(t *testing.T) {
	t.Parallel()

	sites, err := parseNginxSites("/etc/nginx/sites-enabled/shop.conf", `
server {
    root /var/www/shop/public;

    location = /index.php {
        fastcgi_pass unix:/run/php/shop.sock;
    }

    location ~* \.(php|phtml|phar)$ {
        fastcgi_pass unix:/run/php/shop.sock;
    }

    location ~ ^/uploads/.*\.(phtml|phar)$ {
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
	if !site.HasGenericPHPLocation {
		t.Fatalf("expected alternate executable php extensions to count as generic php handling, got %+v", site)
	}
	if !site.UploadExecutionAllowed {
		t.Fatalf("expected upload-adjacent alternate php extensions to count as upload execution, got %+v", site)
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

func TestSnapshotServiceDiscoversNginxSitesFromCommand(t *testing.T) {
	t.Parallel()

	service := newTestSnapshotService()
	service.commandsEnabled = true
	service.nginxCommand = "/www/server/nginx/sbin/nginx"
	service.lookPath = func(name string) (string, error) {
		if name == "/www/server/nginx/sbin/nginx" {
			return name, nil
		}
		return "", fs.ErrNotExist
	}
	service.runCommand = func(_ context.Context, command model.CommandRequest) (model.CommandResult, error) {
		if command.Name != "/www/server/nginx/sbin/nginx" || len(command.Args) != 1 || command.Args[0] != "-T" {
			t.Fatalf("unexpected command %+v", command)
		}
		return model.CommandResult{
			ExitCode: 0,
			Stdout: `
# configuration file /www/server/nginx/conf/nginx.conf:
server {
    server_name app.hypersender.com;
    root /www/wwwroot/app.hypersender.com/current/public;
    location ~ \.php$ {
        fastcgi_pass unix:/tmp/php-cgi-83.sock;
    }
}
`,
		}, nil
	}

	snapshot, unknowns, err := service.Discover(context.Background(), model.ExecutionContext{
		Config: model.AuditConfig{Scope: model.ScanScopeHost},
	})
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if len(unknowns) != 0 {
		t.Fatalf("expected no unknowns, got %+v", unknowns)
	}
	if len(snapshot.NginxSites) != 1 {
		t.Fatalf("expected nginx site from command output, got %+v", snapshot.NginxSites)
	}
	if snapshot.NginxSites[0].Root != "/www/wwwroot/app.hypersender.com/current/public" {
		t.Fatalf("unexpected nginx site %+v", snapshot.NginxSites[0])
	}
}

func TestSnapshotServiceReportsConfiguredMissingNginxBinary(t *testing.T) {
	t.Parallel()

	service := newTestSnapshotService()
	service.commandsEnabled = true
	service.nginxCommand = "/www/server/nginx/sbin/nginx"
	service.lookPath = func(name string) (string, error) {
		return "", fs.ErrNotExist
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
	if unknowns[0].Title != "Configured Nginx binary was not found" {
		t.Fatalf("unexpected unknown %+v", unknowns[0])
	}
	if !strings.Contains(unknowns[0].Reason, "services.nginx.binary") {
		t.Fatalf("expected config hint, got %+v", unknowns[0])
	}
}

func TestSnapshotServiceReportsNginxFallbackWhenBinaryMissingFromPath(t *testing.T) {
	t.Parallel()

	configRoot := t.TempDir()
	nginxConfigPath := filepath.Join(configRoot, "nginx", "shop.conf")
	if err := os.MkdirAll(filepath.Dir(nginxConfigPath), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	writeTestFile(t, nginxConfigPath, "server { root /var/www/shop/public; }")

	service := newTestSnapshotService()
	service.commandsEnabled = true
	service.nginxPatterns = []string{nginxConfigPath}
	service.lookPath = func(name string) (string, error) {
		return "", fs.ErrNotExist
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
	if unknowns[0].Title != "Nginx binary was not found on PATH" {
		t.Fatalf("unexpected unknown %+v", unknowns[0])
	}
	if !strings.Contains(unknowns[0].Reason, "services.nginx.binary") {
		t.Fatalf("expected config hint, got %+v", unknowns[0])
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

func TestCollectArtifactRecordsCapturesPublicPHPOutsideUploadPaths(t *testing.T) {
	t.Parallel()

	rootPath := t.TempDir()
	if err := os.MkdirAll(filepath.Join(rootPath, "public"), 0o755); err != nil {
		t.Fatalf("MkdirAll(public) error = %v", err)
	}
	writeTestFile(t, filepath.Join(rootPath, "public/index.php"), "<?php echo 'front';\n")
	writeTestFile(t, filepath.Join(rootPath, "public/probe.php"), "<?php echo 'probe';\n")

	service := newTestSnapshotService()
	artifacts, unknowns := service.collectArtifactRecords(context.Background(), rootPath)
	if len(unknowns) != 0 {
		t.Fatalf("expected no unknowns, got %+v", unknowns)
	}
	if len(artifacts) != 1 || artifacts[0].Kind != model.ArtifactKindPublicPHPFile || artifacts[0].Path.RelativePath != "public/probe.php" {
		t.Fatalf("expected only non-front-controller public php artifact, got %+v", artifacts)
	}
	if artifacts[0].UploadLikePath {
		t.Fatalf("expected non-upload public php artifact, got %+v", artifacts[0])
	}
}

func TestCollectArtifactRecordsCapturesAlternateExecutablePHPExtensions(t *testing.T) {
	t.Parallel()

	rootPath := t.TempDir()
	if err := os.MkdirAll(filepath.Join(rootPath, "public/uploads"), 0o755); err != nil {
		t.Fatalf("MkdirAll(public/uploads) error = %v", err)
	}
	if err := os.MkdirAll(filepath.Join(rootPath, "storage/app"), 0o755); err != nil {
		t.Fatalf("MkdirAll(storage/app) error = %v", err)
	}
	writeTestFile(t, filepath.Join(rootPath, "public/shell.phtml"), "<?php echo 'shell';\n")
	writeTestFile(t, filepath.Join(rootPath, "public/uploads/dropper.phar"), "<?php echo 'dropper';\n")
	writeTestFile(t, filepath.Join(rootPath, "storage/app/persist.php5"), "<?php echo 'persist';\n")

	service := newTestSnapshotService()
	artifacts, unknowns := service.collectArtifactRecords(context.Background(), rootPath)
	if len(unknowns) != 0 {
		t.Fatalf("expected no unknowns, got %+v", unknowns)
	}
	if len(artifacts) != 3 {
		t.Fatalf("expected 3 executable php-family artifacts, got %+v", artifacts)
	}
	if artifacts[0].Path.RelativePath != "public/shell.phtml" || artifacts[0].Kind != model.ArtifactKindPublicPHPFile {
		t.Fatalf("expected public phtml artifact first, got %+v", artifacts)
	}
	if artifacts[1].Path.RelativePath != "public/uploads/dropper.phar" || !artifacts[1].UploadLikePath {
		t.Fatalf("expected upload-like public phar artifact second, got %+v", artifacts)
	}
	if artifacts[2].Path.RelativePath != "storage/app/persist.php5" || artifacts[2].Kind != model.ArtifactKindWritablePHPFile {
		t.Fatalf("expected writable php5 artifact third, got %+v", artifacts)
	}
}

func TestCollectArtifactRecordsCapturesPublicSymlinkArtifacts(t *testing.T) {
	t.Parallel()

	rootPath := t.TempDir()
	if err := os.MkdirAll(filepath.Join(rootPath, "public"), 0o755); err != nil {
		t.Fatalf("MkdirAll(public) error = %v", err)
	}
	if err := os.MkdirAll(filepath.Join(rootPath, "storage/app/private"), 0o755); err != nil {
		t.Fatalf("MkdirAll(storage/app/private) error = %v", err)
	}
	if err := os.Symlink(filepath.Join(rootPath, "storage/app/private"), filepath.Join(rootPath, "public/private-link")); err != nil {
		t.Fatalf("Symlink(public/private-link) error = %v", err)
	}

	service := newTestSnapshotService()
	artifacts, unknowns := service.collectArtifactRecords(context.Background(), rootPath)
	if len(unknowns) != 0 {
		t.Fatalf("expected no unknowns, got %+v", unknowns)
	}
	if len(artifacts) != 1 || artifacts[0].Kind != model.ArtifactKindPublicSymlink {
		t.Fatalf("expected public symlink artifact, got %+v", artifacts)
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
