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

func newTestSnapshotService() SnapshotService {
	service := NewService()
	service.nginxPatterns = nil
	service.phpFPMPatterns = nil
	service.phpINIPatterns = nil
	service.mysqlPatterns = nil
	service.supervisorPatterns = nil
	service.systemdPatterns = nil
	service.cronPatterns = nil
	service.discoverSupervisor = false
	service.discoverMySQL = false
	service.discoverSystemd = false
	service.discoverCron = false
	service.discoverListeners = false
	service.sshPatterns = nil
	service.sudoersPatterns = nil
	service.discoverSSH = false
	service.discoverSudo = false
	service.discoverFirewall = false
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
	config.Profile.Paths.MySQLConfigPatterns = []string{"/srv/mysql/*.cnf"}
	config.Profile.Commands.PHPFPMBinaries = []string{"/opt/php/83/sbin/php-fpm"}
	config.Profile.Switches.DiscoverNginx = false
	config.Profile.Switches.DiscoverMySQL = false

	service := NewServiceForAudit(config)

	if service.discoverNginx {
		t.Fatal("expected nginx discovery to be disabled from profile switches")
	}

	if !service.discoverPHPFPM {
		t.Fatal("expected php-fpm discovery to remain enabled")
	}
	if service.discoverMySQL {
		t.Fatal("expected mysql discovery to be disabled from profile switches")
	}

	if len(service.nginxPatterns) != 1 || service.nginxPatterns[0] != "/srv/nginx/*.conf" {
		t.Fatalf("unexpected nginx patterns %+v", service.nginxPatterns)
	}

	if len(service.phpFPMPatterns) != 1 || service.phpFPMPatterns[0] != "/srv/php-fpm/*.conf" {
		t.Fatalf("unexpected php-fpm patterns %+v", service.phpFPMPatterns)
	}
	if len(service.mysqlPatterns) != 1 || service.mysqlPatterns[0] != "/srv/mysql/*.cnf" {
		t.Fatalf("unexpected mysql patterns %+v", service.mysqlPatterns)
	}
	if len(service.phpFPMCommands) != 1 || service.phpFPMCommands[0] != "/opt/php/83/sbin/php-fpm" {
		t.Fatalf("unexpected php-fpm commands %+v", service.phpFPMCommands)
	}
}

func TestNewServiceUsesSafeOperationalDefaults(t *testing.T) {
	t.Parallel()

	service := NewService()

	if service.lookPath == nil || service.readFile == nil || service.runCommand == nil {
		t.Fatalf("expected constructor to initialize core dependencies: %+v", service)
	}
	if !service.discoverNginx || !service.discoverPHPFPM || !service.discoverMySQL || !service.discoverSupervisor || !service.discoverSystemd {
		t.Fatalf("expected core service discovery defaults to be enabled: %+v", service)
	}
	if !service.discoverCron || !service.discoverListeners || !service.discoverSSH || !service.discoverSudo || !service.discoverFirewall {
		t.Fatalf("expected operational discovery defaults to be enabled: %+v", service)
	}
	if len(service.nginxPatterns) == 0 || len(service.phpFPMPatterns) == 0 || len(service.mysqlPatterns) == 0 || len(service.supervisorPatterns) == 0 || len(service.systemdPatterns) == 0 {
		t.Fatalf("expected built-in config patterns, got %+v", service)
	}
	if len(service.cronPatterns) == 0 || len(service.sshPatterns) == 0 || len(service.sudoersPatterns) == 0 {
		t.Fatalf("expected built-in operational patterns, got %+v", service)
	}
	if len(service.sshAccountPatterns) == 0 {
		t.Fatalf("expected built-in ssh account patterns, got %+v", service)
	}
	if service.lookupUserName == nil || service.lookupGroupName == nil {
		t.Fatalf("expected identity lookup helpers, got %+v", service)
	}

	if _, err := service.runCommand(context.Background(), model.CommandRequest{Name: "ss"}); !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("expected default runCommand to deny execution, got %v", err)
	}
}

func TestNewServiceForAuditUsesSupervisorAndSystemdOverrides(t *testing.T) {
	t.Parallel()

	config := model.DefaultAuditConfig()
	config.Profile.Paths.UseDefaultPatterns = false
	config.Profile.Paths.SupervisorConfigPatterns = []string{"/srv/supervisor/*.conf"}
	config.Profile.Paths.SystemdUnitPatterns = []string{"/srv/systemd/*.service"}
	config.Profile.Commands.SupervisorBinary = "/opt/supervisor/bin/supervisord"
	config.Profile.Switches.DiscoverSupervisor = false
	config.Profile.Switches.DiscoverSystemd = false

	service := NewServiceForAudit(config)

	if service.discoverSupervisor || service.discoverSystemd {
		t.Fatalf("expected supervisor and systemd discovery to be disabled: %+v", service)
	}
	if len(service.supervisorPatterns) != 1 || service.supervisorPatterns[0] != "/srv/supervisor/*.conf" {
		t.Fatalf("unexpected supervisor patterns %+v", service.supervisorPatterns)
	}
	if len(service.systemdPatterns) != 1 || service.systemdPatterns[0] != "/srv/systemd/*.service" {
		t.Fatalf("unexpected systemd patterns %+v", service.systemdPatterns)
	}
	if service.supervisorCommand != "/opt/supervisor/bin/supervisord" {
		t.Fatalf("unexpected supervisor command %q", service.supervisorCommand)
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
	if app.LaravelVersion != "v11.9.0" {
		t.Fatalf("expected laravel version metadata, got %+v", app)
	}
	if app.PHPVersion != "" {
		t.Fatalf("expected empty php version when composer.json omits php, got %+v", app)
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

func TestSnapshotServiceAutoScopePrefersExplicitAppOverScanRoots(t *testing.T) {
	t.Parallel()

	scanRoot := t.TempDir()
	explicitAppRoot := createLaravelTestApp(t, filepath.Join(scanRoot, "sites/shop/current"), false)
	_ = createLaravelTestApp(t, filepath.Join(scanRoot, "sites/blog/current"), false)

	service := newTestSnapshotService()
	service.lookPath = func(name string) (string, error) {
		return "", errors.New("missing")
	}

	snapshot, unknowns, err := service.Discover(context.Background(), model.ExecutionContext{
		Config: model.AuditConfig{
			Scope:     model.ScanScopeAuto,
			AppPath:   explicitAppRoot,
			ScanRoots: []string{scanRoot},
		},
	})
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}

	if len(unknowns) != 0 {
		t.Fatalf("expected no unknowns, got %+v", unknowns)
	}
	if len(snapshot.Apps) != 1 {
		t.Fatalf("expected only the explicit app, got %+v", snapshot.Apps)
	}
	if snapshot.Apps[0].RootPath != explicitAppRoot {
		t.Fatalf("expected explicit app root %q, got %+v", explicitAppRoot, snapshot.Apps)
	}
}

func TestSnapshotServiceAutoScopeFallsBackToScanRootsWhenExplicitAppInvalid(t *testing.T) {
	t.Parallel()

	scanRoot := t.TempDir()
	discoveredAppRoot := createLaravelTestApp(t, filepath.Join(scanRoot, "sites/shop/current"), false)
	missingAppRoot := filepath.Join(scanRoot, "sites/missing/current")

	service := newTestSnapshotService()
	service.lookPath = func(name string) (string, error) {
		return "", errors.New("missing")
	}

	snapshot, unknowns, err := service.Discover(context.Background(), model.ExecutionContext{
		Config: model.AuditConfig{
			Scope:     model.ScanScopeAuto,
			AppPath:   missingAppRoot,
			ScanRoots: []string{scanRoot},
		},
	})
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}

	if len(snapshot.Apps) != 1 || snapshot.Apps[0].RootPath != discoveredAppRoot {
		t.Fatalf("expected scan-root fallback app %q, got %+v", discoveredAppRoot, snapshot.Apps)
	}

	foundRequestedUnknown := false
	for _, unknown := range unknowns {
		if unknown.CheckID == appDiscoveryCheckID && strings.Contains(unknown.Title, "Requested app path is not a Laravel application") {
			foundRequestedUnknown = true
			break
		}
	}
	if !foundRequestedUnknown {
		t.Fatalf("expected requested-app fallback unknown, got %+v", unknowns)
	}
}

func TestSnapshotServiceCollectsFortifyAndInertiaPackages(t *testing.T) {
	t.Parallel()

	appRoot := createLaravelTestApp(t, t.TempDir(), false)
	writeTestFile(t, filepath.Join(appRoot, "composer.json"), `{
  "name": "acme/shop",
  "require": {
    "php": "^8.2",
    "laravel/framework": "^11.0",
    "laravel/fortify": "^1.0",
    "inertiajs/inertia-laravel": "^1.0"
  }
}`)
	writeTestFile(t, filepath.Join(appRoot, "composer.lock"), `{
  "packages": [
    {"name": "laravel/framework", "version": "v11.8.0"},
    {"name": "laravel/fortify", "version": "v1.21.0"},
    {"name": "inertiajs/inertia-laravel", "version": "v1.0.0"}
  ]
}`)

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
	if app.PHPVersion != "^8.2" {
		t.Fatalf("expected php version metadata, got %+v", app)
	}
	if app.LaravelVersion != "v11.8.0" {
		t.Fatalf("expected laravel version metadata, got %+v", app)
	}
	if got := packageVersion(app.Packages, "laravel/fortify"); got != "v1.21.0" {
		t.Fatalf("expected fortify package version, got %q", got)
	}
	if got := packageVersion(app.Packages, "inertiajs/inertia-laravel"); got != "v1.0.0" {
		t.Fatalf("expected inertia package version, got %q", got)
	}
}

func TestSnapshotServiceCollectsReleaseLayoutMetadata(t *testing.T) {
	t.Parallel()

	deployRoot := t.TempDir()
	currentPath := filepath.Join(deployRoot, "current")
	currentReleasePath := filepath.Join(deployRoot, "releases", "20260312")
	previousReleasePath := filepath.Join(deployRoot, "releases", "20260310")
	sharedPath := filepath.Join(deployRoot, "shared")

	createLaravelTestApp(t, currentReleasePath, false)
	createLaravelTestApp(t, previousReleasePath, false)
	if err := os.MkdirAll(sharedPath, 0o755); err != nil {
		t.Fatalf("MkdirAll(shared) error = %v", err)
	}
	if err := os.Symlink(currentReleasePath, currentPath); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}

	service := newTestSnapshotService()
	service.lookPath = func(name string) (string, error) { return "", errors.New("missing") }

	snapshot, unknowns, err := service.Discover(context.Background(), model.ExecutionContext{
		Config: model.AuditConfig{
			Scope:   model.ScanScopeApp,
			AppPath: currentPath,
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

	deployment := snapshot.Apps[0].Deployment
	expectedReleaseRoot, err := filepath.EvalSymlinks(filepath.Join(deployRoot, "releases"))
	if err != nil {
		t.Fatalf("EvalSymlinks(releases) error = %v", err)
	}
	expectedSharedPath, err := filepath.EvalSymlinks(sharedPath)
	if err != nil {
		t.Fatalf("EvalSymlinks(shared) error = %v", err)
	}

	if !deployment.UsesReleaseLayout || deployment.ReleaseRoot != expectedReleaseRoot || deployment.SharedPath != expectedSharedPath || len(deployment.PreviousReleases) != 1 {
		t.Fatalf("unexpected deployment metadata: %+v", deployment)
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
