package checks_test

import (
	"context"
	"testing"

	"github.com/nagi1/larainspect/internal/checks"
	"github.com/nagi1/larainspect/internal/model"
)

func TestAppValidationCheckReportsAmbiguousAndIncompleteRoots(t *testing.T) {
	t.Parallel()

	app := completeLaravelApp("/var/www/shop/current")
	app.ResolvedPath = "/var/www/shop/releases/20260312"
	setMissingPath(&app, "routes")

	result, err := checks.AppValidationCheck{}.Run(context.Background(), model.ExecutionContext{}, model.Snapshot{
		Apps: []model.LaravelApp{app},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if len(result.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %+v", result.Findings)
	}
}

func TestFilesystemPermissionsCheckReportsDangerousEnvironmentPermissions(t *testing.T) {
	t.Parallel()

	app := completeLaravelApp("/var/www/shop")
	setPathRecord(&app, ".env", model.PathKindFile, 0o666)

	result, err := checks.FilesystemPermissionsCheck{}.Run(context.Background(), model.ExecutionContext{}, model.Snapshot{
		Apps: []model.LaravelApp{app},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if len(result.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %+v", result.Findings)
	}

	if result.Findings[0].Severity != model.SeverityCritical && result.Findings[1].Severity != model.SeverityCritical {
		t.Fatalf("expected critical world-writable finding, got %+v", result.Findings)
	}
}

func TestSecretsExposureCheckReportsDebugBackupsAndUploadPHP(t *testing.T) {
	t.Parallel()

	app := completeLaravelApp("/var/www/shop")
	app.Environment = model.EnvironmentInfo{
		AppDebugDefined:   true,
		AppDebugValue:     "true",
		AppEnvDefined:     true,
		AppEnvValue:       "local",
		AppKeyDefined:     false,
		DBPasswordDefined: true,
		DBPasswordEmpty:   true,
	}
	app.Artifacts = []model.ArtifactRecord{
		{
			Kind:             model.ArtifactKindEnvironmentBackup,
			WithinPublicPath: true,
			Path:             newArtifactPathRecord("/var/www/shop", "public/.env.bak"),
		},
		{
			Kind:             model.ArtifactKindPublicSensitiveFile,
			WithinPublicPath: true,
			Path:             newArtifactPathRecord("/var/www/shop", "public/dump.sql"),
		},
		{
			Kind:             model.ArtifactKindPublicPHPFile,
			WithinPublicPath: true,
			UploadLikePath:   true,
			Path:             newArtifactPathRecord("/var/www/shop", "public/uploads/shell.php"),
		},
	}

	result, err := checks.SecretsExposureCheck{}.Run(context.Background(), model.ExecutionContext{}, model.Snapshot{
		Apps: []model.LaravelApp{app},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if len(result.Findings) != 7 {
		t.Fatalf("expected 7 findings, got %+v", result.Findings)
	}

	for _, title := range []string{
		"APP_ENV is set to a development value",
		"Database password is empty in .env",
	} {
		if !findingTitleExists(result.Findings, title) {
			t.Fatalf("expected finding title %q, got %+v", title, result.Findings)
		}
	}
}

func TestSecretsExposureCheckReportsInvalidAppKeyAndReadableConfigCache(t *testing.T) {
	t.Parallel()

	app := completeLaravelApp("/var/www/shop")
	app.Environment.AppKeyDefined = true
	app.Environment.AppKeyValue = "short"
	setPathRecord(&app, "bootstrap/cache/config.php", model.PathKindFile, 0o644)

	result, err := checks.SecretsExposureCheck{}.Run(context.Background(), model.ExecutionContext{}, model.Snapshot{
		Apps: []model.LaravelApp{app},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if len(result.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %+v", result.Findings)
	}
}

func TestNginxBoundaryCheckReportsDocrootExecutionAndMissingDenyRules(t *testing.T) {
	t.Parallel()

	app := completeLaravelApp("/var/www/shop")
	setPathRecord(&app, "public/storage", model.PathKindSymlink, 0o777)

	result, err := checks.NginxBoundaryCheck{}.Run(context.Background(), model.ExecutionContext{}, model.Snapshot{
		Apps: []model.LaravelApp{app},
		NginxSites: []model.NginxSite{{
			ConfigPath:            "/etc/nginx/sites-enabled/shop.conf",
			Root:                  "/var/www/shop",
			HasGenericPHPLocation: true,
			GenericPHPLocations:   []string{`~ \.php$`},
		}},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if len(result.Findings) != 4 {
		t.Fatalf("expected 4 findings, got %+v", result.Findings)
	}
}

func TestNginxBoundaryCheckReportsExecutablePublicPHPArtifacts(t *testing.T) {
	t.Parallel()

	app := completeLaravelApp("/var/www/shop")
	app.Artifacts = []model.ArtifactRecord{
		{
			Kind:             model.ArtifactKindPublicPHPFile,
			WithinPublicPath: true,
			Path:             newArtifactPathRecord("/var/www/shop", "public/probe.php"),
		},
	}

	result, err := checks.NginxBoundaryCheck{}.Run(context.Background(), model.ExecutionContext{}, model.Snapshot{
		Apps: []model.LaravelApp{app},
		NginxSites: []model.NginxSite{{
			ConfigPath:            "/etc/nginx/sites-enabled/shop.conf",
			Root:                  "/var/www/shop/public",
			HasGenericPHPLocation: true,
			GenericPHPLocations:   []string{`~ \.php$`},
		}},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if !findingTitleExists(result.Findings, "Public web directory contains PHP files Nginx may execute directly") {
		t.Fatalf("expected unexpected public php finding, got %+v", result.Findings)
	}
}

func TestNginxBoundaryCheckReportsPublicPHPArtifactsEvenWithoutGenericHandler(t *testing.T) {
	t.Parallel()

	app := completeLaravelApp("/var/www/shop")
	app.Artifacts = []model.ArtifactRecord{
		{
			Kind:             model.ArtifactKindPublicPHPFile,
			WithinPublicPath: true,
			Path:             newArtifactPathRecord("/var/www/shop", "public/status.php"),
		},
	}

	result, err := checks.NginxBoundaryCheck{}.Run(context.Background(), model.ExecutionContext{}, model.Snapshot{
		Apps: []model.LaravelApp{app},
		NginxSites: []model.NginxSite{{
			ConfigPath:             "/etc/nginx/sites-enabled/shop.conf",
			Root:                   "/var/www/shop/public",
			HasFrontControllerOnly: true,
			FrontControllerPaths:   []string{`= /index.php`},
		}},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if !findingTitleExists(result.Findings, "Public web directory contains extra PHP files beyond index.php") {
		t.Fatalf("expected public php boundary finding, got %+v", result.Findings)
	}
}

func TestPHPFPMSecurityCheckReportsRootExposureAndSharedPools(t *testing.T) {
	t.Parallel()

	appOne := completeLaravelApp("/var/www/shop")
	appTwo := completeLaravelApp("/var/www/blog")

	result, err := checks.PHPFPMSecurityCheck{}.Run(context.Background(), model.ExecutionContext{}, model.Snapshot{
		Apps: []model.LaravelApp{appOne, appTwo},
		NginxSites: []model.NginxSite{
			{ConfigPath: "/etc/nginx/sites-enabled/shop.conf", Root: "/var/www/shop/public", FastCGIPassTargets: []string{"unix:/run/php/shared.sock"}},
			{ConfigPath: "/etc/nginx/sites-enabled/blog.conf", Root: "/var/www/blog/public", FastCGIPassTargets: []string{"unix:/run/php/shared.sock"}},
		},
		PHPFPMPools: []model.PHPFPMPool{
			{
				ConfigPath: "/etc/php/8.3/fpm/pool.d/www.conf",
				Name:       "www",
				User:       "root",
				Listen:     "0.0.0.0:9000",
				ListenMode: "0666",
			},
			{
				ConfigPath:  "/etc/php/8.3/fpm/pool.d/shared.conf",
				Name:        "shared",
				User:        "www-data",
				Listen:      "/run/php/shared.sock",
				ListenOwner: "www-data",
				ListenGroup: "www-data",
				ListenMode:  "0666",
			},
		},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if len(result.Findings) != 5 {
		t.Fatalf("expected 5 findings, got %+v", result.Findings)
	}
}

func TestFilesystemPermissionsCheckReportsRuntimeWritableCodeAndRuntimeOwnedEnv(t *testing.T) {
	t.Parallel()

	app := completeLaravelApp("/var/www/shop")
	app.RootRecord.OwnerName = "www-data"
	setPathRecord(&app, "app", model.PathKindDirectory, 0o770)
	setPathOwnership(&app, "app", "deploy", "www-data")
	setPathOwnership(&app, ".env", "www-data", "www-data")

	result, err := checks.FilesystemPermissionsCheck{}.Run(context.Background(), model.ExecutionContext{}, model.Snapshot{
		Apps: []model.LaravelApp{app},
		NginxSites: []model.NginxSite{{
			ConfigPath:         "/etc/nginx/sites-enabled/shop.conf",
			Root:               "/var/www/shop/public",
			FastCGIPassTargets: []string{"unix:/run/php/shop.sock"},
		}},
		PHPFPMPools: []model.PHPFPMPool{{
			ConfigPath: "/etc/php/8.3/fpm/pool.d/shop.conf",
			Name:       "shop",
			User:       "www-data",
			Group:      "www-data",
			Listen:     "/run/php/shop.sock",
			ListenMode: "0660",
		}},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if len(result.Findings) != 4 {
		t.Fatalf("expected 4 findings, got %+v", result.Findings)
	}

	for _, title := range []string{
		".env is owned by the web or worker user",
		"App directory is owned by the web or worker user",
		"Web or worker user can change app code or config",
		"Laravel file permissions are broader than needed",
	} {
		if !findingTitleExists(result.Findings, title) {
			t.Fatalf("expected finding title %q, got %+v", title, result.Findings)
		}
	}
}

func TestFilesystemPermissionsCheckReportsWritablePathBaselineDrift(t *testing.T) {
	t.Parallel()

	app := completeLaravelApp("/var/www/shop")
	setPathRecord(&app, "storage", model.PathKindDirectory, 0o750)
	setPathOwnership(&app, "storage", "deploy", "deploy")

	result, err := checks.FilesystemPermissionsCheck{}.Run(context.Background(), model.ExecutionContext{}, model.Snapshot{
		Apps: []model.LaravelApp{app},
		NginxSites: []model.NginxSite{{
			ConfigPath:         "/etc/nginx/sites-enabled/shop.conf",
			Root:               "/var/www/shop/public",
			FastCGIPassTargets: []string{"unix:/run/php/shop.sock"},
		}},
		PHPFPMPools: []model.PHPFPMPool{{
			ConfigPath: "/etc/php/8.3/fpm/pool.d/shop.conf",
			Name:       "shop",
			User:       "www-data",
			Group:      "www-data",
			Listen:     "/run/php/shop.sock",
			ListenMode: "0660",
		}},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if len(result.Findings) != 1 || result.Findings[0].Title != "Laravel writable directories do not match the expected safe setup" {
		t.Fatalf("expected writable baseline finding, got %+v", result.Findings)
	}
}

func TestNginxBoundaryCheckReportsUnexpectedPublicStorageSymlinkTarget(t *testing.T) {
	t.Parallel()

	app := completeLaravelApp("/var/www/shop/current")
	setPathRecord(&app, "public/storage", model.PathKindSymlink, 0o770)
	setPathOwnership(&app, "public/storage", "deploy", "www-data")
	for index, pathRecord := range app.KeyPaths {
		if pathRecord.RelativePath != "public/storage" {
			continue
		}

		app.KeyPaths[index].ResolvedPath = "/var/www/shop/shared/private"
		app.KeyPaths[index].TargetKind = model.PathKindDirectory
		break
	}

	result, err := checks.NginxBoundaryCheck{}.Run(context.Background(), model.ExecutionContext{}, model.Snapshot{
		Apps: []model.LaravelApp{app},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if len(result.Findings) != 1 || result.Findings[0].Title != "public/storage points somewhere other than Laravel's normal public disk" {
		t.Fatalf("expected unexpected public/storage symlink finding, got %+v", result.Findings)
	}
}

func TestNginxBoundaryCheckReportsPublicStorageExposureControl(t *testing.T) {
	t.Parallel()

	app := completeLaravelApp("/var/www/shop/current")
	setPathRecord(&app, "public/storage", model.PathKindSymlink, 0o770)
	setPathOwnership(&app, "public/storage", "deploy", "www-data")
	for index, pathRecord := range app.KeyPaths {
		if pathRecord.RelativePath != "public/storage" {
			continue
		}

		app.KeyPaths[index].ResolvedPath = "/var/www/shop/shared/storage/app/public"
		app.KeyPaths[index].TargetKind = model.PathKindDirectory
		break
	}
	app.Deployment = model.DeploymentInfo{
		UsesReleaseLayout: true,
		CurrentPath:       "/var/www/shop/current",
		ReleaseRoot:       "/var/www/shop/releases",
		SharedPath:        "/var/www/shop/shared",
	}

	result, err := checks.NginxBoundaryCheck{}.Run(context.Background(), model.ExecutionContext{}, model.Snapshot{
		Apps: []model.LaravelApp{app},
		NginxSites: []model.NginxSite{{
			ConfigPath:           "/etc/nginx/sites-enabled/shop.conf",
			Root:                 "/var/www/shop/current/public",
			HiddenFilesDenied:    true,
			SensitiveFilesDenied: true,
		}},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if len(result.Findings) != 1 || result.Findings[0].Title != "public/storage makes public-disk files reachable over the web" {
		t.Fatalf("expected public/storage exposure control finding, got %+v", result.Findings)
	}
}

func TestNginxBoundaryCheckReportsConditionalPublicStorageBoundaryWithoutMatchedSite(t *testing.T) {
	t.Parallel()

	app := completeLaravelApp("/var/www/shop/current")
	setPathRecord(&app, "public/storage", model.PathKindSymlink, 0o770)
	setPathOwnership(&app, "public/storage", "deploy", "www-data")
	for index, pathRecord := range app.KeyPaths {
		if pathRecord.RelativePath != "public/storage" {
			continue
		}

		app.KeyPaths[index].ResolvedPath = "/var/www/shop/current/storage/app/public"
		app.KeyPaths[index].TargetKind = model.PathKindDirectory
		break
	}

	result, err := checks.NginxBoundaryCheck{}.Run(context.Background(), model.ExecutionContext{}, model.Snapshot{
		Apps: []model.LaravelApp{app},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if len(result.Findings) != 1 {
		t.Fatalf("expected one finding, got %+v", result.Findings)
	}
	if result.Findings[0].Title != "public/storage exposes files through the web path and should be reviewed" {
		t.Fatalf("expected conditional public/storage control finding, got %+v", result.Findings)
	}
	if result.Findings[0].Severity != model.SeverityInformational {
		t.Fatalf("expected informational severity, got %+v", result.Findings[0])
	}
}

func TestNginxBoundaryCheckReportsPrivatePublicSymlink(t *testing.T) {
	t.Parallel()

	app := completeLaravelApp("/var/www/shop/current")
	app.Artifacts = []model.ArtifactRecord{{
		Kind: model.ArtifactKindPublicSymlink,
		Path: model.PathRecord{
			RelativePath: "public/private-assets",
			AbsolutePath: "/var/www/shop/current/public/private-assets",
			ResolvedPath: "/var/www/shop/current/storage/app/private",
			PathKind:     model.PathKindSymlink,
			TargetKind:   model.PathKindDirectory,
			Inspected:    true,
			Exists:       true,
			Permissions:  0o777,
			OwnerName:    "deploy",
			GroupName:    "www-data",
		},
	}}

	result, err := checks.NginxBoundaryCheck{}.Run(context.Background(), model.ExecutionContext{}, model.Snapshot{
		Apps: []model.LaravelApp{app},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if len(result.Findings) != 1 || result.Findings[0].Title != "A symlink inside public/ points to a private app path" {
		t.Fatalf("expected private public symlink finding, got %+v", result.Findings)
	}
}

func completeLaravelApp(rootPath string) model.LaravelApp {
	app := model.LaravelApp{
		RootPath: rootPath,
		RootRecord: model.PathRecord{
			RelativePath: ".",
			AbsolutePath: rootPath,
			PathKind:     model.PathKindDirectory,
			TargetKind:   model.PathKindDirectory,
			Inspected:    true,
			Exists:       true,
			Permissions:  0o750,
			OwnerName:    "deploy",
			GroupName:    "www-data",
		},
		Environment: model.EnvironmentInfo{
			AppDebugDefined: true,
			AppDebugValue:   "false",
			AppKeyDefined:   true,
			AppKeyValue:     "base64:dGVzdHRlc3R0ZXN0dGVzdA==",
		},
	}

	for _, expectation := range model.CoreLaravelPathExpectations() {
		if !expectation.Required && expectation.RelativePath != ".env" && expectation.RelativePath != "bootstrap/cache/config.php" {
			continue
		}

		permissions := uint32(0o750)
		switch expectation.RelativePath {
		case "storage", "storage/logs", "bootstrap/cache":
			permissions = 0o770
		case "bootstrap/cache/config.php":
			permissions = 0o660
		default:
			if expectation.Kind == model.PathKindFile {
				permissions = 0o640
			}
		}
		if expectation.RelativePath == ".env" {
			permissions = 0o640
		}

		app.KeyPaths = append(app.KeyPaths, model.PathRecord{
			RelativePath: expectation.RelativePath,
			AbsolutePath: rootPath + "/" + expectation.RelativePath,
			PathKind:     expectation.Kind,
			TargetKind:   expectation.Kind,
			Inspected:    true,
			Exists:       true,
			Permissions:  permissions,
			OwnerName:    "deploy",
			GroupName:    "www-data",
		})
	}

	model.SortPathRecords(app.KeyPaths)

	return app
}

func setMissingPath(app *model.LaravelApp, relativePath string) {
	for index, pathRecord := range app.KeyPaths {
		if pathRecord.RelativePath != relativePath {
			continue
		}

		app.KeyPaths[index].Exists = false
		return
	}
}

func setPathRecord(app *model.LaravelApp, relativePath string, kind model.PathKind, permissions uint32) {
	for index, pathRecord := range app.KeyPaths {
		if pathRecord.RelativePath != relativePath {
			continue
		}

		app.KeyPaths[index].PathKind = kind
		app.KeyPaths[index].TargetKind = kind
		app.KeyPaths[index].Permissions = permissions
		app.KeyPaths[index].Exists = true
		app.KeyPaths[index].Inspected = true
		return
	}

	app.KeyPaths = append(app.KeyPaths, model.PathRecord{
		RelativePath: relativePath,
		AbsolutePath: app.RootPath + "/" + relativePath,
		PathKind:     kind,
		TargetKind:   kind,
		Inspected:    true,
		Exists:       true,
		Permissions:  permissions,
		OwnerName:    "deploy",
		GroupName:    "www-data",
	})
	model.SortPathRecords(app.KeyPaths)
}

func setPathOwnership(app *model.LaravelApp, relativePath string, owner string, group string) {
	for index, pathRecord := range app.KeyPaths {
		if pathRecord.RelativePath != relativePath {
			continue
		}

		app.KeyPaths[index].OwnerName = owner
		app.KeyPaths[index].GroupName = group
		return
	}
}

func newArtifactPathRecord(rootPath string, relativePath string) model.PathRecord {
	return model.PathRecord{
		RelativePath: relativePath,
		AbsolutePath: rootPath + "/" + relativePath,
		PathKind:     model.PathKindFile,
		TargetKind:   model.PathKindFile,
		Inspected:    true,
		Exists:       true,
		Permissions:  0o644,
		OwnerName:    "deploy",
		GroupName:    "www-data",
	}
}
