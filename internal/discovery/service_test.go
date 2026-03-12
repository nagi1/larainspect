package discovery

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/nagi/larainspect/internal/model"
)

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

func TestSnapshotServiceDiscoversToolsAndExplicitLaravelApp(t *testing.T) {
	t.Parallel()

	appRoot := createLaravelTestApp(t, t.TempDir(), true)
	service := NewService()
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

	service := NewService()
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
	service := NewService()
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
	service := NewService()
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

	service := NewService()
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

	service := NewService()
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

	service := NewService()
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
  {"name": "laravel/horizon", "version": "v5.0.0"}
]`)

	service := NewService()
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
}

func TestSnapshotServiceNormalizesScanRootWalkFailuresIntoUnknowns(t *testing.T) {
	t.Parallel()

	service := NewService()
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

	service := NewService()
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
		"bootstrap",
		"public",
		"vendor/composer",
	} {
		if err := os.MkdirAll(filepath.Join(root, relativePath), 0o755); err != nil {
			t.Fatalf("MkdirAll(%q) error = %v", relativePath, err)
		}
	}

	writeTestFile(t, filepath.Join(root, "artisan"), "#!/usr/bin/env php\n")
	writeTestFile(t, filepath.Join(root, "bootstrap/app.php"), "<?php return app();\n")
	writeTestFile(t, filepath.Join(root, "public/index.php"), "<?php require __DIR__.'/../vendor/autoload.php';\n")
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
