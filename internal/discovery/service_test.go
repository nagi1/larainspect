package discovery

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/nagi1/larainspect/internal/model"
)

func newTestSnapshotService() SnapshotService {
	service := NewService()
	service.nginxPatterns = nil
	service.phpFPMPatterns = nil
	return service
}

func TestNoopServiceReturnsHostAndTools(t *testing.T) {
	t.Parallel()

	execution := model.ExecutionContext{
		Host:  model.Host{Hostname: "demo"},
		Tools: model.ToolAvailability{"stat": true},
	}

	snapshot, unknowns, err := NoopService{}.Discover(context.Background(), execution)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}

	if len(unknowns) != 0 {
		t.Fatalf("expected no unknowns, got %d", len(unknowns))
	}

	if snapshot.Host.Hostname != "demo" || !snapshot.Tools["stat"] {
		t.Fatalf("unexpected snapshot: %+v", snapshot)
	}
}

func TestNewServiceForAuditUsesProfileDrivenDiscoverySettings(t *testing.T) {
	t.Parallel()

	config := model.DefaultAuditConfig()
	config.Profile.OSFamily = "fedora"
	config.Profile.Paths.UseDefaultPatterns = false
	config.Profile.Paths.NginxConfigPatterns = []string{"/srv/nginx/*.conf"}
	config.Profile.Paths.PHPFPMPoolPatterns = []string{"/srv/php-fpm/*.conf"}
	config.Profile.Switches.DiscoverNginx = false

	service := NewServiceForAudit(config)

	if service.discoverNginx {
		t.Fatal("expected nginx discovery to be disabled from profile switches")
	}

	if !service.discoverPHPFPM {
		t.Fatal("expected php-fpm discovery to remain enabled")
	}

	if len(service.nginxPatterns) != 1 || service.nginxPatterns[0] != "/srv/nginx/*.conf" {
		t.Fatalf("unexpected nginx patterns %+v", service.nginxPatterns)
	}

	if len(service.phpFPMPatterns) != 1 || service.phpFPMPatterns[0] != "/srv/php-fpm/*.conf" {
		t.Fatalf("unexpected php-fpm patterns %+v", service.phpFPMPatterns)
	}
}

func TestSnapshotServiceDiscoversToolsAndExplicitLaravelApp(t *testing.T) {
	t.Parallel()

	appRoot := createLaravelTestApp(t, t.TempDir(), true)
	service := newTestSnapshotService()
	service.lookPath = func(name string) (string, error) {
		switch name {
		case "hostname", "find", "php-fpm":
			return "/usr/bin/" + name, nil
		default:
			return "", errors.New("missing")
		}
	}

	snapshot, unknowns, err := service.Discover(context.Background(), model.ExecutionContext{
		Host: model.Host{Hostname: "demo"},
		Config: model.AuditConfig{
			Scope:   model.ScanScopeApp,
			AppPath: appRoot,
		},
	})
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}

	if len(unknowns) != 0 {
		t.Fatalf("expected no unknowns, got %+v", unknowns)
	}

	if !snapshot.Tools["hostname"] || !snapshot.Tools["find"] || !snapshot.Tools["php-fpm"] {
		t.Fatalf("expected discovered tools, got %+v", snapshot.Tools)
	}

	if len(snapshot.Apps) != 1 {
		t.Fatalf("expected 1 app, got %+v", snapshot.Apps)
	}

	app := snapshot.Apps[0]
	if app.AppName != "acme/shop" {
		t.Fatalf("expected app name from composer.json, got %+v", app)
	}

	if got := packageVersion(app.Packages, "laravel/framework"); got != "v11.9.0" {
		t.Fatalf("expected installed laravel version, got %q", got)
	}

	if got := packageVersion(app.Packages, "filament/filament"); got != "^3.2" {
		t.Fatalf("expected composer manifest fallback for filament, got %q", got)
	}
}

func TestSnapshotServiceDiscoversLaravelAppsFromScanRoots(t *testing.T) {
	t.Parallel()

	scanRoot := t.TempDir()
	firstAppRoot := createLaravelTestApp(t, filepath.Join(scanRoot, "sites/shop"), false)
	secondAppRoot := createLaravelTestApp(t, filepath.Join(scanRoot, "sites/blog/current"), false)

	service := newTestSnapshotService()
	service.lookPath = func(name string) (string, error) {
		return "", errors.New("missing")
	}

	snapshot, unknowns, err := service.Discover(context.Background(), model.ExecutionContext{
		Config: model.AuditConfig{
			Scope:     model.ScanScopeAuto,
			ScanRoots: []string{scanRoot, scanRoot},
		},
	})
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}

	if len(unknowns) != 0 {
		t.Fatalf("expected no unknowns, got %+v", unknowns)
	}

	if len(snapshot.Apps) != 2 {
		t.Fatalf("expected 2 apps, got %+v", snapshot.Apps)
	}

	discoveredRoots := map[string]bool{}
	for _, app := range snapshot.Apps {
		discoveredRoots[app.RootPath] = true
	}

	if !discoveredRoots[firstAppRoot] || !discoveredRoots[secondAppRoot] {
		t.Fatalf("expected discovered roots %q and %q, got %+v", firstAppRoot, secondAppRoot, snapshot.Apps)
	}
}

func TestSnapshotServiceSkipsApplicationDiscoveryForHostScope(t *testing.T) {
	t.Parallel()

	appRoot := createLaravelTestApp(t, t.TempDir(), false)
	service := newTestSnapshotService()
	service.lookPath = func(name string) (string, error) {
		return "", errors.New("missing")
	}

	snapshot, unknowns, err := service.Discover(context.Background(), model.ExecutionContext{
		Config: model.AuditConfig{
			Scope:     model.ScanScopeHost,
			AppPath:   appRoot,
			ScanRoots: []string{filepath.Dir(appRoot)},
		},
	})
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}

	if len(unknowns) != 0 {
		t.Fatalf("expected no unknowns, got %+v", unknowns)
	}

	if len(snapshot.Apps) != 0 {
		t.Fatalf("expected no discovered apps for host scope, got %+v", snapshot.Apps)
	}
}

func TestSnapshotServiceNormalizesComposerPermissionFailuresIntoUnknowns(t *testing.T) {
	t.Parallel()

	appRoot := createLaravelTestApp(t, t.TempDir(), true)
	service := newTestSnapshotService()
	service.lookPath = func(name string) (string, error) {
		return "", errors.New("missing")
	}

	originalReadFile := service.readFile
	service.readFile = func(path string) ([]byte, error) {
		if filepath.Clean(path) == filepath.Join(appRoot, "composer.lock") {
			return nil, fs.ErrPermission
		}

		return originalReadFile(path)
	}

	snapshot, unknowns, err := service.Discover(context.Background(), model.ExecutionContext{
		Config: model.AuditConfig{
			Scope:   model.ScanScopeApp,
			AppPath: appRoot,
		},
	})
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}

	if len(snapshot.Apps) != 1 {
		t.Fatalf("expected 1 app, got %+v", snapshot.Apps)
	}

	if len(unknowns) != 1 {
		t.Fatalf("expected 1 unknown, got %+v", unknowns)
	}

	if unknowns[0].Error != model.ErrorKindPermissionDenied {
		t.Fatalf("expected permission denied unknown, got %+v", unknowns[0])
	}
}

func TestSnapshotServiceReportsUnknownForMissingRequestedAppPath(t *testing.T) {
	t.Parallel()

	service := newTestSnapshotService()
	service.lookPath = func(name string) (string, error) {
		return "", errors.New("missing")
	}

	missingPath := filepath.Join(t.TempDir(), "missing")
	snapshot, unknowns, err := service.Discover(context.Background(), model.ExecutionContext{
		Config: model.AuditConfig{
			Scope:   model.ScanScopeApp,
			AppPath: missingPath,
		},
	})
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}

	if len(snapshot.Apps) != 0 {
		t.Fatalf("expected no apps, got %+v", snapshot.Apps)
	}

	if len(unknowns) != 1 {
		t.Fatalf("expected 1 unknown, got %+v", unknowns)
	}

	if unknowns[0].Error != model.ErrorKindNotEnoughData {
		t.Fatalf("expected not_enough_data unknown, got %+v", unknowns[0])
	}
}

func TestSnapshotServiceReportsUnknownForNonLaravelRequestedAppPath(t *testing.T) {
	t.Parallel()

	rootPath := t.TempDir()
	writeTestFile(t, filepath.Join(rootPath, "README.md"), "not a laravel app\n")

	service := newTestSnapshotService()
	service.lookPath = func(name string) (string, error) {
		return "", errors.New("missing")
	}

	snapshot, unknowns, err := service.Discover(context.Background(), model.ExecutionContext{
		Config: model.AuditConfig{
			Scope:   model.ScanScopeApp,
			AppPath: rootPath,
		},
	})
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}

	if len(snapshot.Apps) != 0 {
		t.Fatalf("expected no apps, got %+v", snapshot.Apps)
	}

	if len(unknowns) != 1 {
		t.Fatalf("expected 1 unknown, got %+v", unknowns)
	}

	if unknowns[0].Title != "Requested app path is not a Laravel application" {
		t.Fatalf("expected requested-app-path unknown, got %+v", unknowns[0])
	}
}

func TestSnapshotServiceNormalizesComposerParseFailuresIntoUnknowns(t *testing.T) {
	t.Parallel()

	appRoot := createLaravelTestApp(t, t.TempDir(), true)
	writeTestFile(t, filepath.Join(appRoot, "composer.json"), "{invalid json")

	service := newTestSnapshotService()
	service.lookPath = func(name string) (string, error) {
		return "", errors.New("missing")
	}

	snapshot, unknowns, err := service.Discover(context.Background(), model.ExecutionContext{
		Config: model.AuditConfig{
			Scope:   model.ScanScopeApp,
			AppPath: appRoot,
		},
	})
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}

	if len(snapshot.Apps) != 1 {
		t.Fatalf("expected 1 app, got %+v", snapshot.Apps)
	}

	if len(unknowns) != 1 {
		t.Fatalf("expected 1 unknown, got %+v", unknowns)
	}

	if unknowns[0].Error != model.ErrorKindParseFailure {
		t.Fatalf("expected parse failure unknown, got %+v", unknowns[0])
	}
}

func TestSnapshotServiceSupportsInstalledPackagesArrayFormat(t *testing.T) {
	t.Parallel()

	appRoot := createLaravelTestApp(t, t.TempDir(), true)
	writeTestFile(t, filepath.Join(appRoot, "vendor/composer/installed.json"), `[
  {"name": "laravel/framework", "version": "v11.10.0"},
  {"name": "laravel/horizon", "version": "v5.0.0"},
  {"name": "laravel/telescope", "version": "v6.0.0"}
]`)

	service := newTestSnapshotService()
	service.lookPath = func(name string) (string, error) {
		return "", errors.New("missing")
	}

	snapshot, unknowns, err := service.Discover(context.Background(), model.ExecutionContext{
		Config: model.AuditConfig{
			Scope:   model.ScanScopeApp,
			AppPath: appRoot,
		},
	})
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}

	if len(unknowns) != 0 {
		t.Fatalf("expected no unknowns, got %+v", unknowns)
	}

	if got := packageVersion(snapshot.Apps[0].Packages, "laravel/framework"); got != "v11.10.0" {
		t.Fatalf("expected array-format installed.json version, got %q", got)
	}

	if got := packageVersion(snapshot.Apps[0].Packages, "laravel/horizon"); got != "v5.0.0" {
		t.Fatalf("expected horizon package, got %q", got)
	}

	if got := packageVersion(snapshot.Apps[0].Packages, "laravel/telescope"); got != "v6.0.0" {
		t.Fatalf("expected telescope package, got %q", got)
	}
}

func TestSnapshotServiceCollectsAppMetadataForCoreChecks(t *testing.T) {
	t.Parallel()

	appRoot := createLaravelTestApp(t, t.TempDir(), true)
	writeTestFile(t, filepath.Join(appRoot, ".env"), "APP_KEY=base64:test-key\nAPP_DEBUG=true\n")
	if err := os.MkdirAll(filepath.Join(appRoot, "public/uploads"), 0o755); err != nil {
		t.Fatalf("MkdirAll(public/uploads) error = %v", err)
	}
	writeTestFile(t, filepath.Join(appRoot, "public/.env.bak"), "APP_KEY=backup\n")
	writeTestFile(t, filepath.Join(appRoot, "public/uploads/shell.php"), "<?php echo 'hi';\n")
	writeTestFile(t, filepath.Join(appRoot, "public/dump.sql"), "-- sql dump\n")

	service := newTestSnapshotService()
	service.lookPath = func(name string) (string, error) {
		return "", errors.New("missing")
	}

	snapshot, unknowns, err := service.Discover(context.Background(), model.ExecutionContext{
		Config: model.AuditConfig{
			Scope:   model.ScanScopeApp,
			AppPath: appRoot,
		},
	})
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}

	if len(unknowns) != 0 {
		t.Fatalf("expected no unknowns, got %+v", unknowns)
	}

	if len(snapshot.Apps) != 1 {
		t.Fatalf("expected 1 app, got %+v", snapshot.Apps)
	}

	app := snapshot.Apps[0]
	envPath, found := app.PathRecord(".env")
	if !found || !envPath.Inspected || !envPath.Exists {
		t.Fatalf("expected inspected .env path, got %+v", envPath)
	}

	if !app.Environment.AppDebugDefined || app.Environment.AppDebugValue != "true" {
		t.Fatalf("expected APP_DEBUG=true metadata, got %+v", app.Environment)
	}

	if !app.Environment.AppKeyDefined {
		t.Fatalf("expected APP_KEY metadata, got %+v", app.Environment)
	}

	if len(app.Artifacts) < 3 {
		t.Fatalf("expected artifact metadata, got %+v", app.Artifacts)
	}
}

func TestSnapshotServiceCollectsFrameworkSourceMatchesAndAdminToolArtifacts(t *testing.T) {
	t.Parallel()

	appRoot := createLaravelTestApp(t, t.TempDir(), true)
	writeTestFile(t, filepath.Join(appRoot, "routes/web.php"), `<?php
use Illuminate\Support\Facades\Route;

Route::prefix('admin')->group(function () {
    Route::get('/dashboard', DashboardController::class);
    Route::post('/login', LoginController::class);
});
`)
	writeTestFile(t, filepath.Join(appRoot, "bootstrap/app.php"), `<?php
return Application::configure(basePath: dirname(__DIR__))
    ->withMiddleware(function ($middleware) {
        $middleware->trustProxies(at: '*');
        $middleware->validateCsrfTokens(except: ['*']);
    });
`)
	writeTestFile(t, filepath.Join(appRoot, "config/livewire.php"), `<?php
return [
    'temporary_file_upload' => [
        'disk' => 'public',
        'directory' => 'livewire-tmp',
    ],
];
`)
	if err := os.MkdirAll(filepath.Join(appRoot, "app/Livewire"), 0o755); err != nil {
		t.Fatalf("MkdirAll(app/Livewire) error = %v", err)
	}
	writeTestFile(t, filepath.Join(appRoot, "app/Livewire/EditTenant.php"), `<?php
namespace App\Livewire;

use Livewire\Component;
use Livewire\WithFileUploads;

class EditTenant extends Component
{
    use WithFileUploads;

    public $tenant_id;

    public function save(): void
    {
        $tenant->save();
    }
}
`)
	if err := os.MkdirAll(filepath.Join(appRoot, "app/Providers/Filament"), 0o755); err != nil {
		t.Fatalf("MkdirAll(app/Providers/Filament) error = %v", err)
	}
	writeTestFile(t, filepath.Join(appRoot, "app/Providers/Filament/AdminPanelProvider.php"), `<?php
namespace App\Providers\Filament;

use Filament\Panel;

class AdminPanelProvider
{
    public function panel(Panel $panel): Panel
    {
        return $panel->path('admin');
    }
}
`)
	writeTestFile(t, filepath.Join(appRoot, "public/adminer.php"), "<?php echo 'adminer';\n")

	service := newTestSnapshotService()
	service.lookPath = func(name string) (string, error) {
		return "", errors.New("missing")
	}

	snapshot, unknowns, err := service.Discover(context.Background(), model.ExecutionContext{
		Config: model.AuditConfig{
			Scope:   model.ScanScopeApp,
			AppPath: appRoot,
		},
	})
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}

	if len(unknowns) != 0 {
		t.Fatalf("expected no unknowns, got %+v", unknowns)
	}

	app := snapshot.Apps[0]
	for _, ruleID := range []string{
		"laravel.route.admin_path",
		"laravel.csrf.except_all",
		"laravel.trusted_proxies.wildcard",
		"livewire.component.with_file_uploads",
		"livewire.component.public_sensitive_property",
		"filament.panel.path.admin",
	} {
		if !sourceMatchExists(app.SourceMatches, ruleID) {
			t.Fatalf("expected source match %q, got %+v", ruleID, app.SourceMatches)
		}
	}

	if !artifactKindExists(app.Artifacts, model.ArtifactKindPublicAdminTool) {
		t.Fatalf("expected public admin tool artifact, got %+v", app.Artifacts)
	}
}

func TestSnapshotServiceNormalizesScanRootWalkFailuresIntoUnknowns(t *testing.T) {
	t.Parallel()

	service := newTestSnapshotService()
	service.lookPath = func(name string) (string, error) {
		return "", errors.New("missing")
	}
	service.walkDirectory = func(root string, walkFn fs.WalkDirFunc) error {
		return fs.ErrPermission
	}

	_, unknowns, err := service.Discover(context.Background(), model.ExecutionContext{
		Config: model.AuditConfig{
			Scope:     model.ScanScopeAuto,
			ScanRoots: []string{"/restricted"},
		},
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

func TestSnapshotServiceStopsDiscoveryWhenContextIsCanceled(t *testing.T) {
	t.Parallel()

	service := newTestSnapshotService()
	service.lookPath = func(name string) (string, error) {
		return "", errors.New("missing")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	snapshot, unknowns, err := service.Discover(ctx, model.ExecutionContext{
		Config: model.AuditConfig{
			Scope:   model.ScanScopeApp,
			AppPath: createLaravelTestApp(t, t.TempDir(), false),
		},
	})
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}

	if len(snapshot.Apps) != 0 {
		t.Fatalf("expected canceled discovery to stop before apps, got %+v", snapshot.Apps)
	}

	if len(unknowns) != 0 {
		t.Fatalf("expected canceled discovery to avoid synthetic unknowns, got %+v", unknowns)
	}
}

func TestParseInstalledPackagesFileRejectsInvalidJSON(t *testing.T) {
	t.Parallel()

	if _, err := parseInstalledPackagesFile([]byte("{")); err == nil {
		t.Fatal("expected invalid installed-packages JSON to fail")
	}
}

func createLaravelTestApp(t *testing.T, root string, includeInstalledPackages bool) string {
	t.Helper()

	for _, relativePath := range []string{
		"app",
		"bootstrap/cache",
		"config",
		"database",
		"public",
		"resources",
		"routes",
		"storage",
		"vendor/composer",
	} {
		if err := os.MkdirAll(filepath.Join(root, relativePath), 0o755); err != nil {
			t.Fatalf("MkdirAll(%q) error = %v", relativePath, err)
		}
	}

	writeTestFile(t, filepath.Join(root, "artisan"), "#!/usr/bin/env php\n")
	writeTestFile(t, filepath.Join(root, "bootstrap/app.php"), "<?php return app();\n")
	configCachePath := filepath.Join(root, "bootstrap/cache/config.php")
	writeTestFile(t, configCachePath, "<?php return ['app' => ['debug' => false]];\n")
	if err := os.Chmod(configCachePath, 0o640); err != nil {
		t.Fatalf("Chmod(%q) error = %v", configCachePath, err)
	}
	writeTestFile(t, filepath.Join(root, "config/app.php"), "<?php return ['name' => 'Demo'];\n")
	writeTestFile(t, filepath.Join(root, "public/index.php"), "<?php require __DIR__.'/../vendor/autoload.php';\n")
	envPath := filepath.Join(root, ".env")
	writeTestFile(t, envPath, "APP_KEY=base64:dGVzdHRlc3R0ZXN0dGVzdA==\nAPP_DEBUG=false\n")
	if err := os.Chmod(envPath, 0o640); err != nil {
		t.Fatalf("Chmod(%q) error = %v", envPath, err)
	}
	writeTestFile(t, filepath.Join(root, "composer.json"), `{
  "name": "acme/shop",
  "require": {
    "laravel/framework": "^11.0",
    "filament/filament": "^3.2"
  }
}`)
	writeTestFile(t, filepath.Join(root, "composer.lock"), `{
  "packages": [
    {"name": "laravel/framework", "version": "v11.8.0"},
    {"name": "livewire/livewire", "version": "v3.5.1"}
  ]
}`)

	if includeInstalledPackages {
		writeTestFile(t, filepath.Join(root, "vendor/composer/installed.json"), `{
  "packages": [
    {"name": "laravel/framework", "version": "v11.9.0"}
  ]
}`)
	}

	return root
}

func writeTestFile(t *testing.T, path string, contents string) {
	t.Helper()

	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", path, err)
	}
}

func packageVersion(packages []model.PackageRecord, name string) string {
	for _, packageRecord := range packages {
		if packageRecord.Name == name {
			return packageRecord.Version
		}
	}

	return ""
}

func sourceMatchExists(matches []model.SourceMatch, ruleID string) bool {
	for _, match := range matches {
		if match.RuleID == ruleID {
			return true
		}
	}

	return false
}

func artifactKindExists(artifacts []model.ArtifactRecord, artifactKind model.ArtifactKind) bool {
	for _, artifact := range artifacts {
		if artifact.Kind == artifactKind {
			return true
		}
	}

	return false
}
