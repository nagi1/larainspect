package checks_test

import (
	"context"
	"testing"

	"github.com/nagi1/larainspect/internal/checks"
	"github.com/nagi1/larainspect/internal/model"
)

func TestSourceSecurityCheckReportsWardInspiredSecuritySignals(t *testing.T) {
	t.Parallel()

	app := completeLaravelApp("/var/www/shop")
	app.SourceMatches = []model.SourceMatch{
		{RuleID: "laravel.auth.login_using_id_variable", RelativePath: "app/Http/Controllers/AuthController.php", Line: 17, Detail: "authenticates with loginUsingId() using a variable"},
		{RuleID: "laravel.security.mass_assignment.guarded_all", RelativePath: "app/Models/User.php", Line: 12, Detail: "marks every model attribute as mass assignable with an empty guarded list"},
		{RuleID: "laravel.security.upload.executable_mimes", RelativePath: "app/Http/Requests/UploadRequest.php", Line: 14, Detail: "allows executable file extensions in upload validation"},
		{RuleID: "laravel.security.upload.risky_web_types", RelativePath: "app/Http/Requests/AvatarUploadRequest.php", Line: 11, Detail: "allows SVG or HTML file types in upload validation"},
		{RuleID: "laravel.security.upload.file_without_constraints", RelativePath: "app/Http/Requests/ImportRequest.php", Line: 9, Detail: "shows a bare file validation rule for an upload field"},
		{RuleID: "laravel.debug.phpinfo_call", RelativePath: "routes/web.php", Line: 6, Detail: "contains a phpinfo() call"},
		{RuleID: "laravel.debug.dd_call", RelativePath: "app/Http/Controllers/TestController.php", Line: 20, Detail: "contains a dd() call"},
		{RuleID: "laravel.debug.dump_call", RelativePath: "app/Http/Controllers/TestController.php", Line: 21, Detail: "contains a dump() call"},
		{RuleID: "laravel.debug.blade_dump_directive", RelativePath: "resources/views/debug.blade.php", Line: 4, Detail: "renders a Blade dump directive"},
		{RuleID: "laravel.xss.blade_raw_request", RelativePath: "resources/views/profile.blade.php", Line: 7, Detail: "renders request-derived data through raw Blade output"},
		{RuleID: "laravel.xss.script_variable_interpolation", RelativePath: "resources/views/profile.blade.php", Line: 11, Detail: "interpolates a PHP variable directly inside a script block"},
		{RuleID: "laravel.inject.db_raw_variable", RelativePath: "app/Models/Report.php", Line: 30, Detail: "uses DB::raw() with a variable or interpolation"},
		{RuleID: "laravel.inject.raw_query_variable", RelativePath: "app/Models/Report.php", Line: 31, Detail: "uses a raw query builder method with a variable or interpolation"},
		{RuleID: "laravel.inject.direct_sql_concat", RelativePath: "app/Models/Report.php", Line: 35, Detail: "builds a direct SQL call using string concatenation and variables"},
		{RuleID: "laravel.inject.shell_exec", RelativePath: "app/Services/BackupService.php", Line: 9, Detail: "calls a shell execution primitive"},
		{RuleID: "laravel.inject.eval", RelativePath: "app/Services/DynamicService.php", Line: 19, Detail: "uses eval()"},
		{RuleID: "laravel.inject.unserialize_variable", RelativePath: "app/Jobs/ImportJob.php", Line: 14, Detail: "unserializes a variable directly"},
	}

	result, err := checks.SourceSecurityCheck{}.Run(context.Background(), model.ExecutionContext{}, model.Snapshot{
		Apps: []model.LaravelApp{app},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if len(result.Findings) != 16 {
		t.Fatalf("expected 16 findings, got %+v", result.Findings)
	}

	for _, title := range []string{
		"loginUsingId() authenticates from a variable",
		"Model uses an empty $guarded list",
		"Upload validation allows executable file types",
		"Upload validation allows SVG or HTML content",
		"Upload validation shows a file rule without obvious type or size constraints",
		"Source contains phpinfo()",
		"Source contains dd()",
		"Source contains debug output helpers",
		"Blade template renders request data through raw output",
		"Blade template interpolates a PHP variable inside a script block",
		"DB::raw() uses a variable or interpolation",
		"Direct SQL call concatenates a variable into query text",
		"Source calls a shell execution primitive",
		"Source uses eval()",
		"Source unserializes a variable directly",
	} {
		if !findingTitleExists(result.Findings, title) {
			t.Fatalf("expected finding title %q, got %+v", title, result.Findings)
		}
	}
}

func TestSourceSecurityCheckSkipsAbsentSignals(t *testing.T) {
	t.Parallel()

	app := completeLaravelApp("/var/www/shop")

	result, err := checks.SourceSecurityCheck{}.Run(context.Background(), model.ExecutionContext{}, model.Snapshot{
		Apps: []model.LaravelApp{app},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings, got %+v", result.Findings)
	}
}

func TestSourceSecurityCheckCorrelatesUploadGapsWithPublicStorageExposure(t *testing.T) {
	t.Parallel()

	app := completeLaravelApp("/var/www/shop")
	setPathRecord(&app, "public/storage", model.PathKindSymlink, 0o770)
	for index, pathRecord := range app.KeyPaths {
		if pathRecord.RelativePath != "public/storage" {
			continue
		}

		app.KeyPaths[index].ResolvedPath = "/var/www/shop/storage/app/public"
		app.KeyPaths[index].TargetKind = model.PathKindDirectory
		break
	}
	app.SourceMatches = []model.SourceMatch{
		{
			RuleID:       "laravel.security.upload.risky_web_types_extension_only",
			RelativePath: "app/Http/Controllers/UploadController.php",
			Line:         14,
			Detail:       "allows SVG or HTML through extension-only upload validation",
		},
	}

	result, err := checks.SourceSecurityCheck{}.Run(context.Background(), model.ExecutionContext{}, model.Snapshot{
		Apps: []model.LaravelApp{app},
		NginxSites: []model.NginxSite{{
			ConfigPath: "/etc/nginx/sites-enabled/shop.conf",
			Root:       "/var/www/shop/public",
		}},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if len(result.Findings) != 1 {
		t.Fatalf("expected one correlated finding, got %+v", result.Findings)
	}
	if result.Findings[0].Title != "Upload validation gaps align with Laravel public storage exposure" {
		t.Fatalf("unexpected finding %+v", result.Findings[0])
	}
}

func TestSourceSecurityCheckSkipsUploadExposureCorrelationWithoutPublicStorageSymlink(t *testing.T) {
	t.Parallel()

	app := completeLaravelApp("/var/www/shop")
	setPathRecord(&app, "public/storage", model.PathKindSymlink, 0o770)
	for index, pathRecord := range app.KeyPaths {
		if pathRecord.RelativePath != "public/storage" {
			continue
		}

		app.KeyPaths[index].ResolvedPath = "/var/www/shop/storage/app/public"
		app.KeyPaths[index].TargetKind = model.PathKindDirectory
		break
	}
	app.SourceMatches = []model.SourceMatch{
		{
			RuleID:       "laravel.security.upload.risky_web_types_extension_only",
			RelativePath: "app/Http/Controllers/UploadController.php",
			Line:         14,
			Detail:       "allows SVG or HTML through extension-only upload validation",
		},
	}

	result, err := checks.SourceSecurityCheck{}.Run(context.Background(), model.ExecutionContext{}, model.Snapshot{
		Apps: []model.LaravelApp{app},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings without a confirmed served boundary or public artifact, got %+v", result.Findings)
	}
}
