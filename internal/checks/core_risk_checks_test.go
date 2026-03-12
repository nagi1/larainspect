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
		AppDebugDefined: true,
		AppDebugValue:   "true",
		AppKeyDefined:   false,
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

	if len(result.Findings) != 5 {
		t.Fatalf("expected 5 findings, got %+v", result.Findings)
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
				ConfigPath: "/etc/php/8.3/fpm/pool.d/shared.conf",
				Name:       "shared",
				User:       "www-data",
				Listen:     "/run/php/shared.sock",
				ListenMode: "0666",
			},
		},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if len(result.Findings) != 4 {
		t.Fatalf("expected 4 findings, got %+v", result.Findings)
	}
}

func completeLaravelApp(rootPath string) model.LaravelApp {
	app := model.LaravelApp{
		RootPath: rootPath,
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

		permissions := uint32(0o755)
		if expectation.Kind == model.PathKindFile {
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
	})
	model.SortPathRecords(app.KeyPaths)
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
	}
}
