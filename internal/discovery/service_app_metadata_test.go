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
	if app.Environment.AppEnvDefined || app.Environment.DBPasswordDefined {
		t.Fatalf("expected APP_ENV and DB_PASSWORD to remain unset, got %+v", app.Environment)
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
	writeTestFile(t, filepath.Join(appRoot, "config/cors.php"), `<?php
return [
    'allowed_origins' => ['*'],
    'supports_credentials' => true,
];
`)
	writeTestFile(t, filepath.Join(appRoot, "config/mail.php"), `<?php
return [
    'password' => 'super-secret-password',
];
`)
	writeTestFile(t, filepath.Join(appRoot, ".env.example"), "DB_PASSWORD=real-pass-123\nMAIL_PASSWORD=changeme\n")
	if err := os.MkdirAll(filepath.Join(appRoot, "app/Http/Controllers"), 0o755); err != nil {
		t.Fatalf("MkdirAll(app/Http/Controllers) error = %v", err)
	}
	writeTestFile(t, filepath.Join(appRoot, "app/Http/Controllers/AuthController.php"), `<?php
use Illuminate\Support\Facades\Auth;

class AuthController
{
    public function impersonate($request): void
    {
        Auth::loginUsingId($request->input('id'));
        eval($payload);
    }
}

func TestSnapshotServiceCollectsAdditionalEnvironmentMetadata(t *testing.T) {
	t.Parallel()

	appRoot := createLaravelTestApp(t, t.TempDir(), true)
	writeTestFile(t, filepath.Join(appRoot, ".env"), "APP_KEY=base64:test-key\nAPP_DEBUG=false\nAPP_ENV=local\nDB_PASSWORD=\n")

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

	environment := snapshot.Apps[0].Environment
	if !environment.AppEnvDefined || environment.AppEnvValue != "local" {
		t.Fatalf("expected APP_ENV metadata, got %+v", environment)
	}
	if !environment.DBPasswordDefined || !environment.DBPasswordEmpty {
		t.Fatalf("expected DB_PASSWORD empty metadata, got %+v", environment)
	}
}
`)
	if err := os.MkdirAll(filepath.Join(appRoot, "app/Models"), 0o755); err != nil {
		t.Fatalf("MkdirAll(app/Models) error = %v", err)
	}
	writeTestFile(t, filepath.Join(appRoot, "app/Models/User.php"), `<?php
class User extends Model
{
    protected $guarded = [];
}
`)
	if err := os.MkdirAll(filepath.Join(appRoot, "resources/views"), 0o755); err != nil {
		t.Fatalf("MkdirAll(resources/views) error = %v", err)
	}
	writeTestFile(t, filepath.Join(appRoot, "resources/views/profile.blade.php"), `{!! request('name') !!}
<script>var state = "{{ $state }}";</script>
@dump($debug)
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
		"laravel.config.cors.wildcard_origins",
		"laravel.config.cors.supports_credentials_true",
		"laravel.config.mail.hardcoded_password",
		"laravel.env.example.real_secret_value",
		"laravel.auth.login_using_id_variable",
		"laravel.security.mass_assignment.guarded_all",
		"laravel.inject.eval",
		"laravel.xss.blade_raw_request",
		"laravel.xss.script_variable_interpolation",
		"laravel.debug.blade_dump_directive",
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

	var file installedPackagesFile
	if err := file.UnmarshalJSON([]byte("{")); err == nil {
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
