package checks

import (
	"context"
	"testing"

	"github.com/nagi1/larainspect/internal/model"
)

func TestHelperFunctionsCoverEdgeCases(t *testing.T) {
	t.Parallel()

	if got := buildFindingID("demo.check", "suffix", ""); got != "demo.check.suffix" {
		t.Fatalf("buildFindingID() with empty path = %q", got)
	}

	app := model.LaravelApp{
		RootPath:     "/var/www/shop/current",
		ResolvedPath: "/var/www/shop/releases/1",
	}
	if !appOwnsServedRoot(app, "/var/www/shop/releases/1/public") {
		t.Fatal("expected appOwnsServedRoot() to match resolved public path")
	}
	if appOwnsServedRoot(app, "/srv/other-app/public") {
		t.Fatal("expected unrelated root to be rejected")
	}
	if !appUsesPublicRoot(app, "/var/www/shop/releases/1/public") {
		t.Fatal("expected appUsesPublicRoot() to match resolved public path")
	}
	if appUsesPublicRoot(app, "/var/www/shop/releases/1") {
		t.Fatal("expected non-public path to be rejected")
	}

	if parsedMode, ok := parseOctalMode("0660"); !ok || parsedMode != 0o660 {
		t.Fatalf("parseOctalMode() = %o ok=%v", parsedMode, ok)
	}
	if _, ok := parseOctalMode("not-a-mode"); ok {
		t.Fatal("expected invalid mode parse to fail")
	}
	if _, ok := parseOctalMode("0"); ok {
		t.Fatal("expected zero-like mode parse to fail")
	}

	evidence := pathEvidence(model.PathRecord{
		AbsolutePath: "/var/www/shop/.env",
		ResolvedPath: "/srv/shared/.env",
		Inspected:    true,
		Exists:       true,
		Permissions:  0o640,
	})
	if len(evidence) != 3 {
		t.Fatalf("expected pathEvidence() to include resolved path evidence, got %+v", evidence)
	}

	sourceEvidence := sourceMatchEvidence(model.LaravelApp{RootPath: "/var/www/shop"}, model.SourceMatch{
		RelativePath: "routes/web.php",
		Line:         12,
		Detail:       "defines an admin-like route path or prefix",
	})
	if len(sourceEvidence) != 3 {
		t.Fatalf("expected sourceMatchEvidence() to include path, line, and detail, got %+v", sourceEvidence)
	}

	app.Packages = []model.PackageRecord{{Name: "livewire/livewire"}}
	if !appUsesPackage(app, "livewire/livewire") {
		t.Fatal("expected appUsesPackage() to detect package metadata")
	}
	if _, found := packageRecordForApp(app, "filament/filament"); found {
		t.Fatal("expected packageRecordForApp() to report missing package")
	}

	app.SourceMatches = []model.SourceMatch{
		{RuleID: "livewire.component.detected", RelativePath: "app/Livewire/EditUser.php"},
		{RuleID: "livewire.component.detected", RelativePath: "app/Livewire/EditUser.php"},
		{RuleID: "filament.file.detected", RelativePath: "app/Filament/Resources/UserResource.php"},
	}
	if len(sourceMatchesWithPrefix(app, "livewire.")) != 2 {
		t.Fatalf("expected sourceMatchesWithPrefix() to preserve both livewire matches, got %+v", app.SourceMatches)
	}
	if len(sourceMatchesForRuleAtRelativePath(app, "livewire.component.detected", "app/Livewire/EditUser.php")) != 2 {
		t.Fatalf("expected sourceMatchesForRuleAtRelativePath() to find duplicate path matches, got %+v", app.SourceMatches)
	}
	relativePaths := uniqueRelativePathsForMatches(app.SourceMatches)
	if len(relativePaths) != 2 {
		t.Fatalf("expected uniqueRelativePathsForMatches() to compact duplicate paths, got %+v", relativePaths)
	}
}

func TestFilesystemPermissionsCheckReportsSymlinkedEnvironmentFile(t *testing.T) {
	t.Parallel()

	app := model.LaravelApp{
		RootPath: "/var/www/shop",
		KeyPaths: []model.PathRecord{
			{
				RelativePath: ".env",
				AbsolutePath: "/var/www/shop/.env",
				ResolvedPath: "/srv/shared/.env",
				PathKind:     model.PathKindSymlink,
				TargetKind:   model.PathKindFile,
				Inspected:    true,
				Exists:       true,
				Permissions:  0o640,
			},
		},
	}

	result, err := FilesystemPermissionsCheck{}.Run(context.Background(), model.ExecutionContext{}, model.Snapshot{
		Apps: []model.LaravelApp{app},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %+v", result.Findings)
	}
}

func TestFilesystemPermissionsCheckSkipsExpectedSharedEnvironmentSymlinkInReleaseLayout(t *testing.T) {
	t.Parallel()

	app := model.LaravelApp{
		RootPath:     "/var/www/shop/current",
		ResolvedPath: "/var/www/shop/releases/20260312",
		Deployment: model.DeploymentInfo{
			UsesReleaseLayout: true,
			CurrentPath:       "/var/www/shop/current",
			ReleaseRoot:       "/var/www/shop/releases",
			SharedPath:        "/var/www/shop/shared",
		},
		KeyPaths: []model.PathRecord{
			{
				RelativePath: ".env",
				AbsolutePath: "/var/www/shop/current/.env",
				ResolvedPath: "/var/www/shop/shared/.env",
				PathKind:     model.PathKindSymlink,
				TargetKind:   model.PathKindFile,
				Inspected:    true,
				Exists:       true,
				Permissions:  0o640,
			},
		},
	}

	result, err := FilesystemPermissionsCheck{}.Run(context.Background(), model.ExecutionContext{}, model.Snapshot{
		Apps: []model.LaravelApp{app},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings, got %+v", result.Findings)
	}
}

func TestNginxAndPHPFPMChecksSkipSafeConfigurations(t *testing.T) {
	t.Parallel()

	app := model.LaravelApp{
		RootPath: "/var/www/shop",
		KeyPaths: []model.PathRecord{
			{
				RelativePath: "public/storage",
				AbsolutePath: "/var/www/shop/public/storage",
				PathKind:     model.PathKindSymlink,
				TargetKind:   model.PathKindDirectory,
				Inspected:    true,
				Exists:       true,
				Permissions:  0o770,
			},
		},
	}

	nginxResult, err := NginxBoundaryCheck{}.Run(context.Background(), model.ExecutionContext{}, model.Snapshot{
		Apps: []model.LaravelApp{app},
		NginxSites: []model.NginxSite{{
			ConfigPath:             "/etc/nginx/sites-enabled/shop.conf",
			Root:                   "/var/www/shop/public",
			HasFrontControllerOnly: true,
			HiddenFilesDenied:      true,
			SensitiveFilesDenied:   true,
		}},
	})
	if err != nil {
		t.Fatalf("NginxBoundaryCheck.Run() error = %v", err)
	}
	if len(nginxResult.Findings) != 0 {
		t.Fatalf("expected no nginx findings, got %+v", nginxResult.Findings)
	}

	phpFPMResult, err := PHPFPMSecurityCheck{}.Run(context.Background(), model.ExecutionContext{}, model.Snapshot{
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
			Listen:     "/run/php/shop.sock",
			ListenMode: "0660",
		}},
	})
	if err != nil {
		t.Fatalf("PHPFPMSecurityCheck.Run() error = %v", err)
	}
	if len(phpFPMResult.Findings) != 0 {
		t.Fatalf("expected no php-fpm findings, got %+v", phpFPMResult.Findings)
	}
}

func TestAppKeyLooksValidAcceptsBase64AndPlaintextFormats(t *testing.T) {
	t.Parallel()

	if !appKeyLooksValid("base64:dGVzdHRlc3R0ZXN0dGVzdA==") {
		t.Fatal("expected valid base64 app key")
	}
	if !appKeyLooksValid("plain-text-key-material") {
		t.Fatal("expected long plaintext app key to be accepted")
	}
	if appKeyLooksValid("base64:%%%") {
		t.Fatal("expected invalid base64 app key to be rejected")
	}
}
