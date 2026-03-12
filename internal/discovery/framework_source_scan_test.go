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

func TestDetectFrameworkSourceMatchesCoversRepresentativeSignals(t *testing.T) {
	t.Parallel()

	routeMatches := detectFrameworkSourceMatches("routes/api.php", `<?php
Route::prefix('admin')->group(function () {
    Route::post('/login', LoginController::class);
});
`)
	if !containsSourceMatch(routeMatches, "laravel.route.admin_path") || !containsSourceMatch(routeMatches, "laravel.route.api_admin_path") {
		t.Fatalf("expected Laravel route heuristic matches, got %+v", routeMatches)
	}

	livewireMatches := detectFrameworkSourceMatches("app/Livewire/EditTenant.php", `<?php
use Livewire\Component;
use Livewire\WithFileUploads;

class EditTenant extends Component
{
    use WithFileUploads;

    public $tenant_id;

    #[Locked]
    public $user_id;

    public function save(): void
    {
        $this->authorize('update');
        $tenant->save();
    }
}
`)
	for _, ruleID := range []string{
		"livewire.component.detected",
		"livewire.component.with_file_uploads",
		"livewire.component.public_sensitive_property",
		"livewire.component.locked_attribute",
		"livewire.component.authorizes_action",
		"livewire.component.mutates_model_state",
	} {
		if !containsSourceMatch(livewireMatches, ruleID) {
			t.Fatalf("expected Livewire rule %q, got %+v", ruleID, livewireMatches)
		}
	}

	filamentMatches := detectFrameworkSourceMatches("app/Filament/Resources/UserResource.php", `<?php
use Filament\Forms\Components\TextInput;

class UserResource
{
    public static function form($form)
    {
        return $form->schema([
            TextInput::make('password'),
        ]);
    }
}
	`)
	if !containsSourceMatch(filamentMatches, "filament.file.detected") ||
		!containsSourceMatch(filamentMatches, "filament.resource.detected") ||
		!containsSourceMatch(filamentMatches, "filament.resource.sensitive_field") {
		t.Fatalf("expected Filament heuristic matches, got %+v", filamentMatches)
	}

	fortifyMatches := detectFrameworkSourceMatches("config/fortify.php", `<?php
use Laravel\Fortify\Features;

return [
    'features' => [
        Features::registration(),
        Features::twoFactorAuthentication(),
    ],
];
`)
	if !containsSourceMatch(fortifyMatches, "fortify.file.detected") ||
		!containsSourceMatch(fortifyMatches, "fortify.feature.registration") ||
		!containsSourceMatch(fortifyMatches, "fortify.feature.two_factor") {
		t.Fatalf("expected Fortify heuristic matches, got %+v", fortifyMatches)
	}

	inertiaMatches := detectFrameworkSourceMatches("app/Http/Middleware/HandleInertiaRequests.php", `<?php
use Inertia\Middleware;

class HandleInertiaRequests extends Middleware
{
    public function share(): array
    {
        return [
            'api_key' => config('services.demo.api_key'),
        ];
    }
}
`)
	if !containsSourceMatch(inertiaMatches, "inertia.file.detected") ||
		!containsSourceMatch(inertiaMatches, "inertia.shared_props.detected") ||
		!containsSourceMatch(inertiaMatches, "inertia.shared_props.sensitive_data") {
		t.Fatalf("expected Inertia heuristic matches, got %+v", inertiaMatches)
	}
}

func TestDetectFrameworkSourceMatchesAvoidsCommentDrivenFalsePositives(t *testing.T) {
	t.Parallel()

	laravelMatches := detectFrameworkSourceMatches("app/Http/Middleware/VerifyCsrfToken.php", `<?php
class VerifyCsrfToken
{
    /*
     * $except = ['*'];
     */
}
`)
	if containsSourceMatch(laravelMatches, "laravel.csrf.except_all") {
		t.Fatalf("did not expect commented CSRF wildcard match, got %+v", laravelMatches)
	}

	routeMatches := detectFrameworkSourceMatches("routes/web.php", `<?php
// Route::get('/admin', fn () => redirect('/login'));
$redirectTarget = '/admin';
`)
	if containsSourceMatch(routeMatches, "laravel.route.admin_path") || containsSourceMatch(routeMatches, "laravel.route.login_path") {
		t.Fatalf("did not expect commented or dead-string route matches, got %+v", routeMatches)
	}

	livewireConfigMatches := detectFrameworkSourceMatches("config/livewire.php", `<?php
return [
    'temporary_file_upload' => [
        'disk' => 'local',
        'directory' => 'tmp-livewire',
    ],
    // public disk uploads are disabled here.
];
`)
	if containsSourceMatch(livewireConfigMatches, "livewire.temporary_upload.public_directory") {
		t.Fatalf("did not expect unrelated public token to match, got %+v", livewireConfigMatches)
	}

	livewireMatches := detectFrameworkSourceMatches("app/Providers/AppServiceProvider.php", `<?php
use Livewire\Component;

class AppServiceProvider
{
    // public $tenant_id;
}
`)
	if containsSourceMatch(livewireMatches, "livewire.component.detected") || containsSourceMatch(livewireMatches, "livewire.component.public_sensitive_property") {
		t.Fatalf("did not expect commented Livewire component/property matches, got %+v", livewireMatches)
	}
}

func TestCollectSourceMatchesFromOptionalFileHandlesEdgeCases(t *testing.T) {
	t.Parallel()

	appRoot := createLaravelTestApp(t, t.TempDir(), false)
	service := newTestSnapshotService()

	writeTestFile(t, filepath.Join(appRoot, "routes/web.php"), "<?php\nRoute::prefix('admin')->group(function () {});\n")

	matches, unknown := service.collectSourceMatchesFromOptionalFile(appRoot, "routes/web.php", map[string]struct{}{})
	if unknown != nil {
		t.Fatalf("collectSourceMatchesFromOptionalFile() unexpected unknown = %+v", unknown)
	}
	if !containsSourceMatch(matches, "laravel.route.admin_path") {
		t.Fatalf("expected route source match, got %+v", matches)
	}

	secondMatches, unknown := service.collectSourceMatchesFromOptionalFile(appRoot, "routes/web.php", map[string]struct{}{"routes/web.php": {}})
	if unknown != nil {
		t.Fatalf("collectSourceMatchesFromOptionalFile() duplicate unexpected unknown = %+v", unknown)
	}
	if len(secondMatches) != 0 {
		t.Fatalf("expected duplicate scan to be skipped, got %+v", secondMatches)
	}

	service.readFile = func(path string) ([]byte, error) {
		return nil, fs.ErrPermission
	}
	_, unknown = service.collectSourceMatchesFromOptionalFile(appRoot, "routes/web.php", map[string]struct{}{})
	if unknown == nil || unknown.Error != model.ErrorKindPermissionDenied {
		t.Fatalf("expected permission denied unknown, got %+v", unknown)
	}
}

func TestCollectSourceMatchesFromOptionalDirectoryHandlesWalkFailures(t *testing.T) {
	t.Parallel()

	appRoot := createLaravelTestApp(t, t.TempDir(), false)
	service := newTestSnapshotService()

	directoryPath := filepath.Join(appRoot, "app/Livewire")
	if err := os.MkdirAll(directoryPath, 0o755); err != nil {
		t.Fatalf("osMkdirAll(app/Livewire) error = %v", err)
	}
	writeTestFile(t, filepath.Join(directoryPath, "EditTenant.php"), "<?php\nuse Livewire\\Component;\nclass EditTenant extends Component {}\n")

	matches, unknowns := service.collectSourceMatchesFromOptionalDirectory(context.Background(), appRoot, "app/Livewire", map[string]struct{}{})
	if len(unknowns) != 0 {
		t.Fatalf("expected no unknowns, got %+v", unknowns)
	}
	if !containsSourceMatch(matches, "livewire.component.detected") {
		t.Fatalf("expected Livewire directory match, got %+v", matches)
	}

	service.walkDirectory = func(root string, walkFn fs.WalkDirFunc) error {
		return errors.New("walk failed")
	}
	_, unknowns = service.collectSourceMatchesFromOptionalDirectory(context.Background(), appRoot, "app/Livewire", map[string]struct{}{})
	if len(unknowns) != 1 || unknowns[0].Title != "Framework source walk failed" {
		t.Fatalf("expected walk failure unknown, got %+v", unknowns)
	}
}

func TestFrameworkSourceHelperFunctions(t *testing.T) {
	t.Parallel()

	if !looksLikeLivewireComponent("app/Livewire/EditTenant.php", "<?php\nuse Livewire\\Component;\nclass EditTenant extends Component {}\n") {
		t.Fatal("expected Livewire component path to match")
	}
	if looksLikeLivewireComponent("app/Models/User.php", "") {
		t.Fatal("expected non-Livewire path to fail")
	}
	if !looksLikeFilamentFile("app/Providers/AdminPanelProvider.php", "use Filament\\Panel;") {
		t.Fatal("expected Filament file signal to match")
	}
	if looksLikeFilamentFile("app/Console/Kernel.php", "") {
		t.Fatal("expected unrelated file to fail Filament detection")
	}
	if !looksLikeFilamentResourceFile("app/Filament/Resources/UserResource.php") {
		t.Fatal("expected Filament resource path to match")
	}
	if looksLikeFilamentResourceFile("app/Filament/Pages/Dashboard.php") {
		t.Fatal("expected non-resource Filament path to fail")
	}
	if !isLikelySecuritySensitiveLivewireProperty("tenant_id") {
		t.Fatal("expected tenant_id to be treated as sensitive")
	}
	if isLikelySecuritySensitiveLivewireProperty("search") {
		t.Fatal("expected search to be treated as non-sensitive")
	}
	if !looksLikeInertiaFile("app/Http/Middleware/HandleInertiaRequests.php", "") {
		t.Fatal("expected Inertia middleware path to match")
	}
	if got := lineNumberForSubstring("one\ntwo", "missing"); got != 0 {
		t.Fatalf("lineNumberForSubstring() missing = %d, want 0", got)
	}
	if got := lineNumberForOffset("one\ntwo\nthree", 5); got != 2 {
		t.Fatalf("lineNumberForOffset() = %d, want 2", got)
	}

	stripped := stripPHPCommentsPreservingNewlines("<?php\n// comment\n'value' /* block */\n")
	if strings.Contains(stripped, "comment") || strings.Contains(stripped, "block") {
		t.Fatalf("expected comments to be stripped, got %q", stripped)
	}
	if !strings.Contains(stripped, "'value'") {
		t.Fatalf("expected string literals to be preserved, got %q", stripped)
	}
}

func containsSourceMatch(matches []model.SourceMatch, ruleID string) bool {
	for _, match := range matches {
		if match.RuleID == ruleID {
			return true
		}
	}

	return false
}
