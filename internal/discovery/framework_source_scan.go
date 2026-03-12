package discovery

import (
	"context"
	"errors"
	"io/fs"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/nagi1/larainspect/internal/model"
)

const (
	maxFrameworkSourceFileBytes         = 256 * 1024
	maxFrameworkSourceFilesPerDirectory = 48
	maxFrameworkSourceDirectoryDepth    = 4
)

var frameworkHeuristicOptionalFiles = []string{
	"app/Http/Middleware/TrustHosts.php",
	"app/Http/Middleware/TrustProxies.php",
	"app/Http/Middleware/VerifyCsrfToken.php",
	"bootstrap/app.php",
	"config/livewire.php",
	"config/session.php",
	"routes/api.php",
	"routes/web.php",
}

var frameworkHeuristicOptionalDirectories = []string{
	"app/Filament",
	"app/Http/Livewire",
	"app/Livewire",
	"app/Providers",
}

var livewireSensitivePublicPropertyPattern = regexp.MustCompile(`(?m)public\s+\$([A-Za-z_][A-Za-z0-9_]*)`)

func (service SnapshotService) collectFrameworkSourceMatches(ctx context.Context, rootPath string) ([]model.SourceMatch, []model.Unknown) {
	matches := []model.SourceMatch{}
	unknowns := []model.Unknown{}
	scannedRelativePaths := map[string]struct{}{}

	for _, relativePath := range frameworkHeuristicOptionalFiles {
		fileMatches, fileUnknown := service.collectSourceMatchesFromOptionalFile(rootPath, relativePath, scannedRelativePaths)
		matches = append(matches, fileMatches...)
		if fileUnknown != nil {
			unknowns = append(unknowns, *fileUnknown)
		}
	}

	for _, relativeDirectoryPath := range frameworkHeuristicOptionalDirectories {
		directoryMatches, directoryUnknowns := service.collectSourceMatchesFromOptionalDirectory(ctx, rootPath, relativeDirectoryPath, scannedRelativePaths)
		matches = append(matches, directoryMatches...)
		unknowns = append(unknowns, directoryUnknowns...)
	}

	model.SortSourceMatches(matches)

	return matches, unknowns
}

func (service SnapshotService) collectSourceMatchesFromOptionalDirectory(
	ctx context.Context,
	rootPath string,
	relativeDirectoryPath string,
	scannedRelativePaths map[string]struct{},
) ([]model.SourceMatch, []model.Unknown) {
	absoluteDirectoryPath := filepath.Join(rootPath, relativeDirectoryPath)
	directoryInfo, err := service.statPath(absoluteDirectoryPath)
	switch {
	case err == nil:
	case errors.Is(err, fs.ErrNotExist):
		return nil, nil
	default:
		unknown := newPathUnknown(appDiscoveryCheckID, "Unable to inspect framework source directory", absoluteDirectoryPath, err)
		return nil, []model.Unknown{unknown}
	}

	if !directoryInfo.IsDir() {
		return nil, nil
	}

	matches := []model.SourceMatch{}
	unknowns := []model.Unknown{}
	scannedFileCount := 0

	walkErr := service.walkDirectory(absoluteDirectoryPath, func(path string, directoryEntry fs.DirEntry, walkErr error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		if walkErr != nil {
			unknowns = append(unknowns, newPathUnknown(appDiscoveryCheckID, "Unable to inspect framework source path", path, walkErr))
			if directoryEntry != nil && directoryEntry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		if directoryEntry.IsDir() {
			if directoryDepth(absoluteDirectoryPath, path) > maxFrameworkSourceDirectoryDepth {
				return filepath.SkipDir
			}
			return nil
		}

		if filepath.Ext(path) != ".php" {
			return nil
		}

		if scannedFileCount >= maxFrameworkSourceFilesPerDirectory {
			return fs.SkipAll
		}

		relativePath, relErr := filepath.Rel(rootPath, path)
		if relErr != nil {
			return nil
		}

		fileMatches, fileUnknown := service.collectSourceMatchesFromOptionalFile(rootPath, relativePath, scannedRelativePaths)
		matches = append(matches, fileMatches...)
		if fileUnknown != nil {
			unknowns = append(unknowns, *fileUnknown)
		}
		scannedFileCount++

		return nil
	})
	switch {
	case walkErr == nil:
	case errors.Is(walkErr, context.Canceled), errors.Is(walkErr, fs.SkipAll):
	default:
		unknowns = append(unknowns, newPathUnknown(appDiscoveryCheckID, "Framework source walk failed", absoluteDirectoryPath, walkErr))
	}

	return matches, unknowns
}

func (service SnapshotService) collectSourceMatchesFromOptionalFile(
	rootPath string,
	relativePath string,
	scannedRelativePaths map[string]struct{},
) ([]model.SourceMatch, *model.Unknown) {
	cleanRelativePath := filepath.Clean(relativePath)
	if _, alreadyScanned := scannedRelativePaths[cleanRelativePath]; alreadyScanned {
		return nil, nil
	}
	scannedRelativePaths[cleanRelativePath] = struct{}{}

	absolutePath := filepath.Join(rootPath, cleanRelativePath)
	fileInfo, err := service.statPath(absolutePath)
	switch {
	case err == nil:
	case errors.Is(err, fs.ErrNotExist):
		return nil, nil
	default:
		unknown := newPathUnknown(appDiscoveryCheckID, "Unable to inspect framework source file", absolutePath, err)
		return nil, &unknown
	}

	if fileInfo.IsDir() || fileInfo.Size() > maxFrameworkSourceFileBytes {
		return nil, nil
	}

	fileBytes, fileUnknown := service.readOptionalFile(absolutePath, "Unable to read framework source file")
	if fileUnknown != nil {
		return nil, fileUnknown
	}
	if len(fileBytes) == 0 {
		return nil, nil
	}

	return detectFrameworkSourceMatches(filepath.ToSlash(cleanRelativePath), string(fileBytes)), nil
}

func detectFrameworkSourceMatches(relativePath string, fileContents string) []model.SourceMatch {
	matches := []model.SourceMatch{}
	matches = append(matches, detectLaravelFrameworkSourceMatches(relativePath, fileContents)...)
	matches = append(matches, detectLivewireFrameworkSourceMatches(relativePath, fileContents)...)
	matches = append(matches, detectFilamentFrameworkSourceMatches(relativePath, fileContents)...)
	model.SortSourceMatches(matches)

	return matches
}

func detectLaravelFrameworkSourceMatches(relativePath string, fileContents string) []model.SourceMatch {
	matches := []model.SourceMatch{}

	if relativePath == "app/Http/Middleware/TrustProxies.php" || relativePath == "bootstrap/app.php" {
		matches = appendSourceMatchIfContainsAny(matches, relativePath, fileContents, "laravel.trusted_proxies.wildcard", "trusts all proxies via a wildcard configuration", []string{
			"protected $proxies = '*'",
			`protected $proxies = "*"`,
			"trustProxies(at: '*')",
			`trustProxies(at: "*")`,
		})
	}

	if relativePath == "app/Http/Middleware/TrustHosts.php" {
		matches = appendSourceMatchIfContainsAny(matches, relativePath, fileContents, "laravel.trusted_hosts.wildcard", "trusts all hosts via a wildcard host allowlist", []string{
			"return ['*']",
			`return ["*"]`,
		})
	}

	if relativePath == "app/Http/Middleware/VerifyCsrfToken.php" || relativePath == "bootstrap/app.php" {
		matches = appendSourceMatchIfContainsAll(matches, relativePath, fileContents, "laravel.csrf.except_all", "disables CSRF coverage broadly with wildcard exclusions", []string{
			"*",
		}, []string{
			"$except = [",
			"validateCsrfTokens(except:",
		})
	}

	if relativePath == "config/session.php" {
		matches = appendSourceMatchIfContainsAny(matches, relativePath, fileContents, "laravel.session.secure_cookie_false", "does not show an obvious secure-cookie default for sessions", []string{
			"'secure' => false",
			"'secure' => env('SESSION_SECURE_COOKIE', false)",
			`"secure" => false`,
			`"secure" => env("SESSION_SECURE_COOKIE", false)`,
		})
	}

	if relativePath == "routes/web.php" || relativePath == "routes/api.php" {
		matches = appendRouteHeuristicMatches(matches, relativePath, fileContents)
	}

	return matches
}

func appendRouteHeuristicMatches(matches []model.SourceMatch, relativePath string, fileContents string) []model.SourceMatch {
	matches = appendSourceMatchIfContainsAny(matches, relativePath, fileContents, "laravel.route.admin_path", "defines an admin-like route path or prefix", []string{
		"Route::prefix('admin'",
		`Route::prefix("admin"`,
		"Route::middleware('admin'",
		`Route::middleware("admin"`,
		"'/admin'",
		`"/admin"`,
	})
	matches = appendSourceMatchIfContainsAny(matches, relativePath, fileContents, "laravel.route.login_path", "defines a custom login route", []string{
		"Route::get('login'",
		`Route::get("login"`,
		"Route::post('login'",
		`Route::post("login"`,
	})
	matches = appendSourceMatchIfContainsAny(matches, relativePath, fileContents, "laravel.route.auth_middleware", "shows explicit auth middleware on route definitions", []string{
		"->middleware('auth",
		`->middleware("auth`,
		"->middleware(['auth",
		`->middleware(["auth`,
		"Authenticate::class",
	})
	matches = appendSourceMatchIfContainsAny(matches, relativePath, fileContents, "laravel.route.throttle_middleware", "shows explicit throttling middleware on route definitions", []string{
		"throttle:",
		"->middleware('throttle",
		`->middleware("throttle`,
		"ThrottleRequests::class",
	})

	if relativePath == "routes/api.php" {
		matches = appendSourceMatchIfContainsAny(matches, relativePath, fileContents, "laravel.route.api_admin_path", "defines an admin-like endpoint inside routes/api.php", []string{
			"Route::prefix('admin'",
			`Route::prefix("admin"`,
			"'/admin'",
			`"/admin"`,
		})
	}

	return matches
}

func detectLivewireFrameworkSourceMatches(relativePath string, fileContents string) []model.SourceMatch {
	matches := []model.SourceMatch{}

	if relativePath == "config/livewire.php" {
		matches = appendSourceMatchIfContainsAll(matches, relativePath, fileContents, "livewire.temporary_upload.public_disk", "stores temporary Livewire uploads on the public disk", []string{
			"temporary_file_upload",
			"'disk' => 'public'",
		}, nil)
		matches = appendSourceMatchIfContainsAll(matches, relativePath, fileContents, "livewire.temporary_upload.public_directory", "uses a public temporary upload directory for Livewire uploads", []string{
			"temporary_file_upload",
			"public",
			"'directory' =>",
		}, nil)
	}

	if !looksLikeLivewireComponent(relativePath, fileContents) {
		return matches
	}

	matches = append(matches, model.SourceMatch{
		RuleID:       "livewire.component.detected",
		RelativePath: relativePath,
		Line:         1,
		Detail:       "detected a Livewire component file",
	})

	matches = appendSourceMatchIfContainsAny(matches, relativePath, fileContents, "livewire.component.with_file_uploads", "uses the WithFileUploads trait", []string{
		"WithFileUploads",
	})
	matches = appendSourceMatchIfContainsAny(matches, relativePath, fileContents, "livewire.component.upload_validation", "shows upload validation or rules near the component", []string{
		"validate(",
		"rules(",
		"#[Validate",
	})
	matches = appendLivewireSensitivePropertyMatches(matches, relativePath, fileContents)
	matches = appendSourceMatchIfContainsAny(matches, relativePath, fileContents, "livewire.component.locked_attribute", "shows a Locked attribute on a public property", []string{
		"#[Locked]",
	})
	matches = appendSourceMatchIfContainsAny(matches, relativePath, fileContents, "livewire.component.mutates_model_state", "mutates model state inside the component", []string{
		"->save(",
		"->update(",
		"::create(",
		"->delete(",
		"forceDelete(",
	})
	matches = appendSourceMatchIfContainsAny(matches, relativePath, fileContents, "livewire.component.authorizes_action", "shows an authorization call inside the component", []string{
		"authorize(",
		"Gate::authorize(",
		"Gate::allows(",
		"->can(",
	})

	return matches
}

func appendLivewireSensitivePropertyMatches(matches []model.SourceMatch, relativePath string, fileContents string) []model.SourceMatch {
	propertyMatches := livewireSensitivePublicPropertyPattern.FindAllStringSubmatchIndex(fileContents, -1)
	for _, propertyMatch := range propertyMatches {
		propertyName := fileContents[propertyMatch[2]:propertyMatch[3]]
		if !isLikelySecuritySensitiveLivewireProperty(propertyName) {
			continue
		}

		lineNumber := lineNumberForOffset(fileContents, propertyMatch[0])
		matches = append(matches, model.SourceMatch{
			RuleID:       "livewire.component.public_sensitive_property",
			RelativePath: relativePath,
			Line:         lineNumber,
			Detail:       "exposes public property $" + propertyName,
		})
	}

	return matches
}

func detectFilamentFrameworkSourceMatches(relativePath string, fileContents string) []model.SourceMatch {
	matches := []model.SourceMatch{}

	if !looksLikeFilamentFile(relativePath, fileContents) {
		return matches
	}

	matches = append(matches, model.SourceMatch{
		RuleID:       "filament.file.detected",
		RelativePath: relativePath,
		Line:         1,
		Detail:       "detected a Filament panel or resource file",
	})

	matches = appendSourceMatchIfContainsAny(matches, relativePath, fileContents, "filament.panel.path.admin", "uses the common /admin Filament panel path", []string{
		"->path('admin')",
		`->path("admin")`,
	})
	matches = appendSourceMatchIfContainsAny(matches, relativePath, fileContents, "filament.panel.auth_middleware", "shows explicit auth middleware on the Filament panel", []string{
		"->authMiddleware(",
		"Authenticate::class",
	})
	matches = appendSourceMatchIfContainsAny(matches, relativePath, fileContents, "filament.panel.tenant_signal", "shows an explicit tenant hook or tenant middleware", []string{
		"->tenant(",
		"->tenantMiddleware(",
		"HasTenants",
	})
	matches = appendSourceMatchIfContainsAny(matches, relativePath, fileContents, "filament.panel.mfa_signal", "shows an MFA or two-factor signal near the Filament panel", []string{
		"twoFactor",
		"TwoFactor",
		"mfa",
		"MFA",
	})
	matches = appendSourceMatchIfContainsAny(matches, relativePath, fileContents, "filament.resource.policy_signal", "shows a policy or authorization signal in a Filament resource", []string{
		"canViewAny(",
		"canEdit(",
		"canDelete(",
		"authorize(",
		"Gate::authorize(",
	})
	matches = appendSourceMatchIfContainsAny(matches, relativePath, fileContents, "filament.resource.tenant_field", "references tenant ownership fields inside Filament resources", []string{
		"tenant_id",
		"team_id",
		"organization_id",
	})
	matches = appendSourceMatchIfContainsAny(matches, relativePath, fileContents, "filament.resource.sensitive_field", "appears to expose a sensitive model field in a Filament form or table", []string{
		"TextInput::make('password'",
		`TextInput::make("password"`,
		"TextColumn::make('password'",
		`TextColumn::make("password"`,
		"Toggle::make('is_admin'",
		`Toggle::make("is_admin"`,
	})

	return matches
}

func looksLikeLivewireComponent(relativePath string, fileContents string) bool {
	return strings.HasPrefix(relativePath, "app/Livewire/") ||
		strings.HasPrefix(relativePath, "app/Http/Livewire/") ||
		strings.Contains(fileContents, "Livewire\\Component")
}

func looksLikeFilamentFile(relativePath string, fileContents string) bool {
	return strings.HasPrefix(relativePath, "app/Filament/") ||
		strings.Contains(fileContents, "Filament\\") ||
		strings.Contains(relativePath, "Filament")
}

func isLikelySecuritySensitiveLivewireProperty(propertyName string) bool {
	switch strings.ToLower(propertyName) {
	case "tenantid", "tenant_id", "teamid", "team_id", "userid", "user_id", "role", "roleid", "role_id", "isadmin", "is_admin":
		return true
	default:
		return false
	}
}

func appendSourceMatchIfContainsAny(
	matches []model.SourceMatch,
	relativePath string,
	fileContents string,
	ruleID string,
	detail string,
	candidates []string,
) []model.SourceMatch {
	for _, candidate := range candidates {
		if !strings.Contains(fileContents, candidate) {
			continue
		}

		matches = append(matches, model.SourceMatch{
			RuleID:       ruleID,
			RelativePath: relativePath,
			Line:         lineNumberForSubstring(fileContents, candidate),
			Detail:       detail,
		})
		return matches
	}

	return matches
}

func appendSourceMatchIfContainsAll(
	matches []model.SourceMatch,
	relativePath string,
	fileContents string,
	ruleID string,
	detail string,
	requiredSubstrings []string,
	anchorSubstrings []string,
) []model.SourceMatch {
	for _, requiredSubstring := range requiredSubstrings {
		if !strings.Contains(fileContents, requiredSubstring) {
			return matches
		}
	}

	for _, anchorSubstring := range anchorSubstrings {
		if !strings.Contains(fileContents, anchorSubstring) {
			continue
		}

		matches = append(matches, model.SourceMatch{
			RuleID:       ruleID,
			RelativePath: relativePath,
			Line:         lineNumberForSubstring(fileContents, anchorSubstring),
			Detail:       detail,
		})
		return matches
	}

	if len(anchorSubstrings) == 0 {
		matches = append(matches, model.SourceMatch{
			RuleID:       ruleID,
			RelativePath: relativePath,
			Line:         1,
			Detail:       detail,
		})
	}

	return matches
}

func lineNumberForSubstring(fileContents string, substring string) int {
	offset := strings.Index(fileContents, substring)
	if offset < 0 {
		return 0
	}

	return lineNumberForOffset(fileContents, offset)
}

func lineNumberForOffset(fileContents string, offset int) int {
	if offset <= 0 {
		return 1
	}

	return strings.Count(fileContents[:offset], "\n") + 1
}
