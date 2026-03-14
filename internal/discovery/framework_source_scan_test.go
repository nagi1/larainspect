package discovery

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
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

	configMatches := detectFrameworkSourceMatches("config/app.php", `<?php
return [
    // 'debug' => true,
    'debug' => env('APP_DEBUG', false),
];
`)
	if containsSourceMatch(configMatches, "laravel.config.app.debug_true") {
		t.Fatalf("did not expect commented config debug match, got %+v", configMatches)
	}
}

func TestDetectFrameworkSourceMatchesCoversConfigAndEnvExampleSignals(t *testing.T) {
	t.Parallel()

	configMatches := detectFrameworkSourceMatches("config/cors.php", `<?php
return [
    'allowed_origins' => ['*'],
    'supports_credentials' => true,
];
`)
	for _, ruleID := range []string{
		"laravel.config.cors.wildcard_origins",
		"laravel.config.cors.supports_credentials_true",
	} {
		if !containsSourceMatch(configMatches, ruleID) {
			t.Fatalf("expected config rule %q, got %+v", ruleID, configMatches)
		}
	}

	mailMatches := detectFrameworkSourceMatches("config/mail.php", `<?php
return [
    'password' => 'super-secret-password',
];
`)
	if !containsSourceMatch(mailMatches, "laravel.config.mail.hardcoded_password") {
		t.Fatalf("expected hardcoded mail password match, got %+v", mailMatches)
	}

	envExampleMatches := detectFrameworkSourceMatches(".env.example", `
DB_PASSWORD=real-pass-123
MAIL_PASSWORD=changeme
`)
	if !containsSourceMatch(envExampleMatches, "laravel.env.example.real_secret_value") {
		t.Fatalf("expected .env.example secret-like match, got %+v", envExampleMatches)
	}

	securityMatches := detectFrameworkSourceMatches("app/Http/Controllers/AuthController.php", `<?php
Auth::loginUsingId($request->input('id'));
$user->whereRaw("name = '$name'");
eval($payload);
$request->validate([
    'avatar' => 'required|file|mimes:svg,png',
    'document' => 'required|file',
]);
`)
	for _, ruleID := range []string{
		"laravel.auth.login_using_id_variable",
		"laravel.inject.raw_query_variable",
		"laravel.inject.eval",
		"laravel.security.upload.risky_web_types",
		"laravel.security.upload.risky_web_types_extension_only",
		"laravel.security.upload.file_without_constraints",
	} {
		if !containsSourceMatch(securityMatches, ruleID) {
			t.Fatalf("expected source security rule %q, got %+v", ruleID, securityMatches)
		}
	}

	mimeOnlyMatches := detectFrameworkSourceMatches("app/Http/Controllers/UploadController.php", `<?php
$request->validate([
    'document' => 'required|file|mimetypes:text/html',
]);
`)
	if !containsSourceMatch(mimeOnlyMatches, "laravel.security.upload.risky_web_types") ||
		!containsSourceMatch(mimeOnlyMatches, "laravel.security.upload.risky_web_types_mime_only") {
		t.Fatalf("expected MIME-only risky upload rules, got %+v", mimeOnlyMatches)
	}

	combinedTypeMatches := detectFrameworkSourceMatches("app/Http/Controllers/SaferUploadController.php", `<?php
$request->validate([
    'document' => 'required|file|mimes:svg|mimetypes:image/svg+xml',
]);
`)
	if containsSourceMatch(combinedTypeMatches, "laravel.security.upload.risky_web_types_extension_only") ||
		containsSourceMatch(combinedTypeMatches, "laravel.security.upload.risky_web_types_mime_only") {
		t.Fatalf("did not expect single-sided risky upload rules when both checks are present, got %+v", combinedTypeMatches)
	}

	bladeMatches := detectFrameworkSourceMatches("resources/views/profile.blade.php", `
{{-- {!! $commented !!} --}}
{!! request('name') !!}
<script>var state = "{{ $state }}";</script>
@dump($debug)
`)
	for _, ruleID := range []string{
		"laravel.xss.blade_raw_request",
		"laravel.xss.script_variable_interpolation",
		"laravel.debug.blade_dump_directive",
	} {
		if !containsSourceMatch(bladeMatches, ruleID) {
			t.Fatalf("expected blade security rule %q, got %+v", ruleID, bladeMatches)
		}
	}
	if containsSourceMatch(bladeMatches, "laravel.xss.blade_raw_variable") {
		t.Fatalf("did not expect commented raw blade output to match, got %+v", bladeMatches)
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
	if got, found := firstMatchingLineNumber("alpha\nbeta\ngamma", regexp.MustCompile(`beta`), nil); !found || got != 2 {
		t.Fatalf("firstMatchingLineNumber() = (%d, %t), want (2, true)", got, found)
	}
	if got, found := firstMatchingLineNumber("alpha env(value)\nbeta", regexp.MustCompile(`env`), []string{"env("}); found || got != 0 {
		t.Fatalf("firstMatchingLineNumber() forbidden = (%d, %t), want (0, false)", got, found)
	}
	envMatches := detectFrameworkSourceMatches(".env.example", "DB_PASSWORD=real-secret-123\nMAIL_PASSWORD=changeme\n")
	if !containsSourceMatch(envMatches, "laravel.env.example.real_secret_value") {
		t.Fatalf("expected yaml env-example rule match, got %+v", envMatches)
	}

	stripped := stripPHPCommentsPreservingNewlines("<?php\n// comment\n'value' /* block */\n")
	if strings.Contains(stripped, "comment") || strings.Contains(stripped, "block") {
		t.Fatalf("expected comments to be stripped, got %q", stripped)
	}
	if !strings.Contains(stripped, "'value'") {
		t.Fatalf("expected string literals to be preserved, got %q", stripped)
	}

	strippedBlade := stripBladeCommentsPreservingNewlines("{{-- secret --}}\n<div>{{ $name }}</div>")
	if strings.Contains(strippedBlade, "secret") || !strings.Contains(strippedBlade, "{{ $name }}") {
		t.Fatalf("unexpected stripBladeCommentsPreservingNewlines() result %q", strippedBlade)
	}

	unclosedBlade := stripBladeCommentsPreservingNewlines("{{-- secret\n<div>")
	if strings.Contains(unclosedBlade, "secret") || !strings.Contains(unclosedBlade, "\n") {
		t.Fatalf("unexpected unclosed blade comment stripping result %q", unclosedBlade)
	}
}

func TestFrameworkSourceAdditionalConfigCoverage(t *testing.T) {
	t.Parallel()

	matches := appendSourceMatchIfContainsAll(nil, "app/Models/User.php", "alpha beta gamma", "rule.all", "matched all", []string{"alpha", "beta"}, []string{"gamma"})
	if !containsSourceMatch(matches, "rule.all") {
		t.Fatalf("expected appendSourceMatchIfContainsAll() to add a match, got %+v", matches)
	}

	lineMatches := appendSourceMatchIfLineMatchesRegex(nil, "config/auth.php", "'expire' => 180", "rule.line", "line matched", regexp.MustCompile(`expire`))
	if !containsSourceMatch(lineMatches, "rule.line") {
		t.Fatalf("expected appendSourceMatchIfLineMatchesRegex() to add a match, got %+v", lineMatches)
	}

	filteredMatches := appendSourceMatchIfLineMatchesRegexWithoutSubstrings(nil, "resources/views/profile.blade.php", "{!! clean($safe) !!}\n{!! $unsafe !!}", "rule.filtered", "filtered match", regexp.MustCompile(`\{!!\s*\$[^!\n]*!!\}`), []string{"clean("})
	if !containsSourceMatch(filteredMatches, "rule.filtered") {
		t.Fatalf("expected appendSourceMatchIfLineMatchesRegexWithoutSubstrings() to keep the unsafe line, got %+v", filteredMatches)
	}

	configCases := []struct {
		path   string
		body   string
		ruleID string
	}{
		{"config/auth.php", "<?php\nreturn ['expire' => 180];\n", "laravel.config.auth.password_reset_expire_long"},
		{"config/session.php", "<?php\nreturn ['http_only' => false, 'same_site' => 'none'];\n", "laravel.config.session.http_only_false"},
		{"config/database.php", "<?php\nreturn ['password' => 'super-secret-password'];\n", "laravel.config.database.hardcoded_password"},
		{"config/broadcasting.php", "<?php\nreturn ['secret' => 'abcdef1234567890'];\n", "laravel.config.broadcasting.hardcoded_secret"},
		{"config/logging.php", "<?php\nreturn ['url' => 'https://hooks.slack.com/services/T1/B1/example'];\n", "laravel.config.logging.hardcoded_slack_webhook"},
	}

	for _, configCase := range configCases {
		configCase := configCase
		t.Run(configCase.path, func(t *testing.T) {
			t.Parallel()

			caseMatches := detectFrameworkSourceMatches(configCase.path, configCase.body)
			if !containsSourceMatch(caseMatches, configCase.ruleID) {
				t.Fatalf("expected config rule %q, got %+v", configCase.ruleID, caseMatches)
			}
		})
	}

	securityMatches := detectFrameworkSourceMatches("resources/views/profile.blade.php", "{!! clean($safe) !!}\n{!! $unsafe !!}\nProcess::run($command);\nexec($command);")
	for _, ruleID := range []string{
		"laravel.xss.blade_raw_variable",
		"laravel.inject.shell_exec",
	} {
		if !containsSourceMatch(securityMatches, ruleID) {
			t.Fatalf("expected security rule %q, got %+v", ruleID, securityMatches)
		}
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
