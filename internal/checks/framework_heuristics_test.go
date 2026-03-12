package checks_test

import (
	"context"
	"testing"

	"github.com/nagi1/larainspect/internal/checks"
	"github.com/nagi1/larainspect/internal/model"
)

func TestFrameworkHeuristicsCheckReportsRepresentativeSignals(t *testing.T) {
	t.Parallel()

	app := completeLaravelApp("/var/www/shop")
	app.Packages = []model.PackageRecord{
		{Name: "laravel/telescope", Version: "v5.0.0", Source: "composer.lock"},
		{Name: "livewire/livewire", Version: "v3.5.1", Source: "composer.lock"},
		{Name: "filament/filament", Version: "^3.2", Source: "composer.json"},
	}
	app.SourceMatches = []model.SourceMatch{
		{RuleID: "laravel.csrf.except_all", RelativePath: "bootstrap/app.php", Line: 5, Detail: "disables CSRF coverage broadly with wildcard exclusions"},
		{RuleID: "laravel.trusted_proxies.wildcard", RelativePath: "bootstrap/app.php", Line: 4, Detail: "trusts all proxies via a wildcard configuration"},
		{RuleID: "laravel.route.admin_path", RelativePath: "routes/web.php", Line: 3, Detail: "defines an admin-like route path or prefix"},
		{RuleID: "laravel.route.login_path", RelativePath: "routes/web.php", Line: 4, Detail: "defines a custom login route"},
		{RuleID: "livewire.component.detected", RelativePath: "app/Livewire/EditTenant.php", Line: 1, Detail: "detected a Livewire component file"},
		{RuleID: "livewire.component.with_file_uploads", RelativePath: "app/Livewire/EditTenant.php", Line: 8, Detail: "uses the WithFileUploads trait"},
		{RuleID: "livewire.component.public_sensitive_property", RelativePath: "app/Livewire/EditTenant.php", Line: 10, Detail: "exposes public property $tenant_id"},
		{RuleID: "livewire.component.mutates_model_state", RelativePath: "app/Livewire/EditTenant.php", Line: 14, Detail: "mutates model state inside the component"},
		{RuleID: "livewire.temporary_upload.public_disk", RelativePath: "config/livewire.php", Line: 4, Detail: "stores temporary Livewire uploads on the public disk"},
		{RuleID: "filament.file.detected", RelativePath: "app/Providers/Filament/AdminPanelProvider.php", Line: 1, Detail: "detected a Filament panel or resource file"},
		{RuleID: "filament.panel.path.admin", RelativePath: "app/Providers/Filament/AdminPanelProvider.php", Line: 9, Detail: "uses the common /admin Filament panel path"},
		{RuleID: "filament.resource.tenant_field", RelativePath: "app/Filament/Resources/UserResource.php", Line: 22, Detail: "references tenant ownership fields inside Filament resources"},
		{RuleID: "filament.resource.sensitive_field", RelativePath: "app/Filament/Resources/UserResource.php", Line: 30, Detail: "appears to expose a sensitive model field in a Filament form or table"},
	}
	app.Artifacts = []model.ArtifactRecord{
		{
			Kind:             model.ArtifactKindPublicAdminTool,
			WithinPublicPath: true,
			Path:             newArtifactPathRecord("/var/www/shop", "public/adminer.php"),
		},
	}

	result, err := checks.FrameworkHeuristicsCheck{}.Run(context.Background(), model.ExecutionContext{}, model.Snapshot{
		Apps: []model.LaravelApp{app},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if len(result.Findings) < 10 {
		t.Fatalf("expected representative heuristic findings, got %+v", result.Findings)
	}

	for _, finding := range result.Findings {
		if finding.Class != model.FindingClassHeuristic {
			t.Fatalf("expected heuristic finding class, got %+v", finding)
		}
	}

	for _, title := range []string{
		"Admin-like routes do not show obvious auth middleware",
		"Livewire component mutates model state without obvious authorization checks",
		"Filament panel appears to use a public /admin path without obvious extra auth middleware",
		"Laravel Telescope package appears present",
		"Public path contains diagnostic or admin tooling",
	} {
		if !findingTitleExists(result.Findings, title) {
			t.Fatalf("expected finding title %q, got %+v", title, result.Findings)
		}
	}
}

func TestFrameworkHeuristicsCheckSkipsHardenedSignals(t *testing.T) {
	t.Parallel()

	app := completeLaravelApp("/var/www/shop")
	app.Packages = []model.PackageRecord{
		{Name: "livewire/livewire", Version: "v3.5.1", Source: "composer.lock"},
		{Name: "filament/filament", Version: "v3.2.0", Source: "composer.lock"},
	}
	app.SourceMatches = []model.SourceMatch{
		{RuleID: "laravel.route.admin_path", RelativePath: "routes/web.php", Line: 3, Detail: "defines an admin-like route path or prefix"},
		{RuleID: "laravel.route.auth_middleware", RelativePath: "routes/web.php", Line: 2, Detail: "shows explicit auth middleware on route definitions"},
		{RuleID: "laravel.route.throttle_middleware", RelativePath: "routes/web.php", Line: 2, Detail: "shows explicit throttling middleware on route definitions"},
		{RuleID: "livewire.component.detected", RelativePath: "app/Livewire/EditTenant.php", Line: 1, Detail: "detected a Livewire component file"},
		{RuleID: "livewire.component.with_file_uploads", RelativePath: "app/Livewire/EditTenant.php", Line: 8, Detail: "uses the WithFileUploads trait"},
		{RuleID: "livewire.component.upload_validation", RelativePath: "app/Livewire/EditTenant.php", Line: 12, Detail: "shows upload validation or rules near the component"},
		{RuleID: "livewire.component.locked_attribute", RelativePath: "app/Livewire/EditTenant.php", Line: 10, Detail: "shows a Locked attribute on a public property"},
		{RuleID: "livewire.component.authorizes_action", RelativePath: "app/Livewire/EditTenant.php", Line: 16, Detail: "shows an authorization call inside the component"},
		{RuleID: "filament.file.detected", RelativePath: "app/Providers/Filament/AdminPanelProvider.php", Line: 1, Detail: "detected a Filament panel or resource file"},
		{RuleID: "filament.panel.path.admin", RelativePath: "app/Providers/Filament/AdminPanelProvider.php", Line: 9, Detail: "uses the common /admin Filament panel path"},
		{RuleID: "filament.panel.auth_middleware", RelativePath: "app/Providers/Filament/AdminPanelProvider.php", Line: 10, Detail: "shows explicit auth middleware on the Filament panel"},
		{RuleID: "filament.panel.tenant_signal", RelativePath: "app/Providers/Filament/AdminPanelProvider.php", Line: 11, Detail: "shows an explicit tenant hook or tenant middleware"},
		{RuleID: "filament.panel.mfa_signal", RelativePath: "app/Providers/Filament/AdminPanelProvider.php", Line: 12, Detail: "shows an MFA or two-factor signal near the Filament panel"},
		{RuleID: "filament.resource.policy_signal", RelativePath: "app/Filament/Resources/UserResource.php", Line: 18, Detail: "shows a policy or authorization signal in a Filament resource"},
	}

	result, err := checks.FrameworkHeuristicsCheck{}.Run(context.Background(), model.ExecutionContext{}, model.Snapshot{
		Apps: []model.LaravelApp{app},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if len(result.Findings) != 0 {
		t.Fatalf("expected no framework heuristic findings, got %+v", result.Findings)
	}
}

func TestFrameworkHeuristicsCheckUsesSourceSignalsWithoutPackageMetadata(t *testing.T) {
	t.Parallel()

	app := completeLaravelApp("/var/www/shop")
	app.SourceMatches = []model.SourceMatch{
		{RuleID: "livewire.component.detected", RelativePath: "app/Livewire/EditTenant.php", Line: 1, Detail: "detected a Livewire component file"},
		{RuleID: "livewire.component.with_file_uploads", RelativePath: "app/Livewire/EditTenant.php", Line: 8, Detail: "uses the WithFileUploads trait"},
	}

	result, err := checks.FrameworkHeuristicsCheck{}.Run(context.Background(), model.ExecutionContext{}, model.Snapshot{
		Apps: []model.LaravelApp{app},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if len(result.Findings) != 1 {
		t.Fatalf("expected one source-driven Livewire heuristic, got %+v", result.Findings)
	}

	if result.Findings[0].Title != "Livewire upload component does not show obvious validation rules" {
		t.Fatalf("unexpected finding %+v", result.Findings[0])
	}
}

func TestFrameworkHeuristicsCheckLowersPackageConfidenceForDeclaredOnlyPackages(t *testing.T) {
	t.Parallel()

	app := completeLaravelApp("/var/www/shop")
	app.Packages = []model.PackageRecord{
		{Name: "laravel/telescope", Version: "^5.0", Source: "composer.json"},
	}

	result, err := checks.FrameworkHeuristicsCheck{}.Run(context.Background(), model.ExecutionContext{}, model.Snapshot{
		Apps: []model.LaravelApp{app},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if len(result.Findings) != 1 {
		t.Fatalf("expected one package heuristic, got %+v", result.Findings)
	}

	finding := result.Findings[0]
	if finding.Severity != model.SeverityMedium || finding.Confidence != model.ConfidencePossible {
		t.Fatalf("expected declared-only package heuristic to stay medium/possible, got %+v", finding)
	}
}

func TestFrameworkHeuristicsCheckKeepsUnsafeLivewireComponentVisibleWhenAnotherComponentIsSafe(t *testing.T) {
	t.Parallel()

	app := completeLaravelApp("/var/www/shop")
	app.Packages = []model.PackageRecord{{Name: "livewire/livewire", Version: "v3.5.1", Source: "composer.lock"}}
	app.SourceMatches = []model.SourceMatch{
		{RuleID: "livewire.component.with_file_uploads", RelativePath: "app/Livewire/SafeUpload.php", Line: 8, Detail: "uses the WithFileUploads trait"},
		{RuleID: "livewire.component.upload_validation", RelativePath: "app/Livewire/SafeUpload.php", Line: 12, Detail: "shows upload validation or rules near the component"},
		{RuleID: "livewire.component.with_file_uploads", RelativePath: "app/Livewire/RiskyUpload.php", Line: 8, Detail: "uses the WithFileUploads trait"},
	}

	result, err := checks.FrameworkHeuristicsCheck{}.Run(context.Background(), model.ExecutionContext{}, model.Snapshot{
		Apps: []model.LaravelApp{app},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if len(result.Findings) != 1 {
		t.Fatalf("expected one finding for the risky component only, got %+v", result.Findings)
	}

	evidence := result.Findings[0].Evidence
	if !evidenceContains(evidence, "/var/www/shop/app/Livewire/RiskyUpload.php") {
		t.Fatalf("expected risky component evidence, got %+v", evidence)
	}
	if evidenceContains(evidence, "/var/www/shop/app/Livewire/SafeUpload.php") {
		t.Fatalf("did not expect safe component evidence, got %+v", evidence)
	}
}

func TestFrameworkHeuristicsCheckKeepsUnsafeFilamentResourceVisibleWhenAnotherResourceHasPolicySignals(t *testing.T) {
	t.Parallel()

	app := completeLaravelApp("/var/www/shop")
	app.Packages = []model.PackageRecord{{Name: "filament/filament", Version: "v3.2.0", Source: "composer.lock"}}
	app.SourceMatches = []model.SourceMatch{
		{RuleID: "filament.resource.detected", RelativePath: "app/Filament/Resources/UserResource.php", Line: 1, Detail: "detected a Filament resource file"},
		{RuleID: "filament.resource.policy_signal", RelativePath: "app/Filament/Resources/UserResource.php", Line: 18, Detail: "shows a policy or authorization signal in a Filament resource"},
		{RuleID: "filament.resource.detected", RelativePath: "app/Filament/Resources/InvoiceResource.php", Line: 1, Detail: "detected a Filament resource file"},
	}

	result, err := checks.FrameworkHeuristicsCheck{}.Run(context.Background(), model.ExecutionContext{}, model.Snapshot{
		Apps: []model.LaravelApp{app},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if len(result.Findings) != 1 {
		t.Fatalf("expected one finding for the risky resource only, got %+v", result.Findings)
	}

	evidence := result.Findings[0].Evidence
	if !evidenceContains(evidence, "/var/www/shop/app/Filament/Resources/InvoiceResource.php") {
		t.Fatalf("expected risky resource evidence, got %+v", evidence)
	}
	if evidenceContains(evidence, "/var/www/shop/app/Filament/Resources/UserResource.php") {
		t.Fatalf("did not expect safe resource evidence, got %+v", evidence)
	}
}

func findingTitleExists(findings []model.Finding, title string) bool {
	for _, finding := range findings {
		if finding.Title == title {
			return true
		}
	}

	return false
}

func evidenceContains(evidence []model.Evidence, detail string) bool {
	for _, item := range evidence {
		if item.Detail == detail {
			return true
		}
	}

	return false
}
