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
