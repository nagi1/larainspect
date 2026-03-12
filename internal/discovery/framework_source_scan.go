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
	"app/Http/Middleware/HandleInertiaRequests.php",
	"bootstrap/app.php",
	"config/fortify.php",
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

var (
	laravelCSRFWildcardExceptPattern              = regexp.MustCompile(`(?s)\$except\s*=\s*\[[^\]]*['"]\*['"][^\]]*\]`)
	laravelCSRFWildcardBootstrapPattern           = regexp.MustCompile(`(?s)validateCsrfTokens\s*\(\s*except:\s*\[[^\]]*['"]\*['"][^\]]*\]`)
	laravelSessionSecureCookieFalsePattern        = regexp.MustCompile(`(?m)['"]secure['"]\s*=>\s*(?:false|env\(\s*['"]SESSION_SECURE_COOKIE['"]\s*,\s*false\s*\))`)
	laravelAdminRoutePrefixPattern                = regexp.MustCompile(`(?m)Route::prefix\(\s*['"]admin(?:/[^'"]*)?['"]`)
	laravelAdminRouteURIPathPattern               = regexp.MustCompile(`(?m)Route::(?:any|delete|get|match|options|patch|post|put|redirect|view)\(\s*['"]/?admin(?:/[^'"]*)?['"]`)
	laravelLoginRoutePathPattern                  = regexp.MustCompile(`(?m)Route::(?:any|get|match|options|patch|post|put|view)\(\s*['"]/?login(?:/[^'"]*)?['"]`)
	laravelAuthMiddlewarePattern                  = regexp.MustCompile(`(?m)(?:->middleware\(\s*(?:\[[^\]]*['"]auth[^'"]*['"][^\]]*\]|['"]auth[^'"]*['"])|Authenticate::class)`)
	laravelThrottleMiddlewarePattern              = regexp.MustCompile(`(?m)(?:->middleware\(\s*(?:\[[^\]]*['"]throttle(?::[^'"]*)?['"][^\]]*\]|['"]throttle(?::[^'"]*)?['"])|ThrottleRequests::class)`)
	livewireTemporaryUploadPublicDiskPattern      = regexp.MustCompile(`(?s)['"]temporary_file_upload['"]\s*=>\s*\[[^\]]*['"]disk['"]\s*=>\s*['"]public['"]`)
	livewireTemporaryUploadPublicDirectoryPattern = regexp.MustCompile(`(?s)['"]temporary_file_upload['"]\s*=>\s*\[[^\]]*['"]directory['"]\s*=>\s*['"][^'"]*public[^'"]*['"]`)
	livewireComponentInheritancePattern           = regexp.MustCompile(`(?s)(?:use\s+Livewire\\Component\s*;.*class\s+[A-Za-z_][A-Za-z0-9_]*\s+extends\s+Component\b|class\s+[A-Za-z_][A-Za-z0-9_]*\s+extends\s+\\?Livewire\\Component\b)`)
	fortifyRegistrationFeaturePattern             = regexp.MustCompile(`Features::registration\s*\(`)
	fortifyTwoFactorFeaturePattern                = regexp.MustCompile(`Features::twoFactorAuthentication\s*\(`)
	inertiaShareSignalPattern                     = regexp.MustCompile(`(?m)(?:Inertia::share\s*\(|function\s+share\s*\([^)]*\)\s*:\s*array)`)
	inertiaSensitiveSharedPropPattern             = regexp.MustCompile(`(?i)\b(password|secret|api[_-]?key|app[_-]?key|private[_-]?key|access[_-]?token|refresh[_-]?token|bearer)\b`)
)

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
	sanitizedFileContents := stripPHPCommentsPreservingNewlines(fileContents)
	matches := []model.SourceMatch{}
	matches = append(matches, detectLaravelFrameworkSourceMatches(relativePath, sanitizedFileContents)...)
	matches = append(matches, detectLivewireFrameworkSourceMatches(relativePath, sanitizedFileContents)...)
	matches = append(matches, detectFilamentFrameworkSourceMatches(relativePath, sanitizedFileContents)...)
	matches = append(matches, detectFortifyFrameworkSourceMatches(relativePath, sanitizedFileContents)...)
	matches = append(matches, detectInertiaFrameworkSourceMatches(relativePath, sanitizedFileContents)...)
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
		matches = appendSourceMatchIfMatchesRegex(matches, relativePath, fileContents, "laravel.csrf.except_all", "disables CSRF coverage broadly with wildcard exclusions", laravelCSRFWildcardExceptPattern)
		matches = appendSourceMatchIfMatchesRegex(matches, relativePath, fileContents, "laravel.csrf.except_all", "disables CSRF coverage broadly with wildcard exclusions", laravelCSRFWildcardBootstrapPattern)
	}

	if relativePath == "config/session.php" {
		matches = appendSourceMatchIfMatchesRegex(matches, relativePath, fileContents, "laravel.session.secure_cookie_false", "does not show an obvious secure-cookie default for sessions", laravelSessionSecureCookieFalsePattern)
	}

	if relativePath == "routes/web.php" || relativePath == "routes/api.php" {
		matches = appendRouteHeuristicMatches(matches, relativePath, fileContents)
	}

	return matches
}

func appendRouteHeuristicMatches(matches []model.SourceMatch, relativePath string, fileContents string) []model.SourceMatch {
	matches = appendSourceMatchIfMatchesAnyRegex(matches, relativePath, fileContents, "laravel.route.admin_path", "defines an admin-like route path or prefix", []*regexp.Regexp{
		laravelAdminRoutePrefixPattern,
		laravelAdminRouteURIPathPattern,
	})
	matches = appendSourceMatchIfMatchesRegex(matches, relativePath, fileContents, "laravel.route.login_path", "defines a custom login route", laravelLoginRoutePathPattern)
	matches = appendSourceMatchIfMatchesRegex(matches, relativePath, fileContents, "laravel.route.auth_middleware", "shows explicit auth middleware on route definitions", laravelAuthMiddlewarePattern)
	matches = appendSourceMatchIfMatchesRegex(matches, relativePath, fileContents, "laravel.route.throttle_middleware", "shows explicit throttling middleware on route definitions", laravelThrottleMiddlewarePattern)

	if relativePath == "routes/api.php" {
		matches = appendSourceMatchIfMatchesAnyRegex(matches, relativePath, fileContents, "laravel.route.api_admin_path", "defines an admin-like endpoint inside routes/api.php", []*regexp.Regexp{
			laravelAdminRoutePrefixPattern,
			laravelAdminRouteURIPathPattern,
		})
	}

	return matches
}

func detectLivewireFrameworkSourceMatches(relativePath string, fileContents string) []model.SourceMatch {
	matches := []model.SourceMatch{}

	if relativePath == "config/livewire.php" {
		matches = appendSourceMatchIfMatchesRegex(matches, relativePath, fileContents, "livewire.temporary_upload.public_disk", "stores temporary Livewire uploads on the public disk", livewireTemporaryUploadPublicDiskPattern)
		matches = appendSourceMatchIfMatchesRegex(matches, relativePath, fileContents, "livewire.temporary_upload.public_directory", "uses a public temporary upload directory for Livewire uploads", livewireTemporaryUploadPublicDirectoryPattern)
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
		"#[Locked",
		"Locked]",
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

	if looksLikeFilamentResourceFile(relativePath) {
		matches = append(matches, model.SourceMatch{
			RuleID:       "filament.resource.detected",
			RelativePath: relativePath,
			Line:         1,
			Detail:       "detected a Filament resource file",
		})
	}

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

func detectFortifyFrameworkSourceMatches(relativePath string, fileContents string) []model.SourceMatch {
	if relativePath != "config/fortify.php" {
		return nil
	}

	matches := []model.SourceMatch{
		{
			RuleID:       "fortify.file.detected",
			RelativePath: relativePath,
			Line:         1,
			Detail:       "detected a Fortify configuration file",
		},
	}
	matches = appendSourceMatchIfMatchesRegex(matches, relativePath, fileContents, "fortify.feature.registration", "enables the Fortify registration feature", fortifyRegistrationFeaturePattern)
	matches = appendSourceMatchIfMatchesRegex(matches, relativePath, fileContents, "fortify.feature.two_factor", "enables the Fortify two-factor authentication feature", fortifyTwoFactorFeaturePattern)

	return matches
}

func detectInertiaFrameworkSourceMatches(relativePath string, fileContents string) []model.SourceMatch {
	if !looksLikeInertiaFile(relativePath, fileContents) {
		return nil
	}

	matches := []model.SourceMatch{
		{
			RuleID:       "inertia.file.detected",
			RelativePath: relativePath,
			Line:         1,
			Detail:       "detected an Inertia middleware or shared-props file",
		},
	}
	matches = appendSourceMatchIfMatchesRegex(matches, relativePath, fileContents, "inertia.shared_props.detected", "defines Inertia shared props", inertiaShareSignalPattern)
	if inertiaShareSignalPattern.MatchString(fileContents) {
		matches = appendSourceMatchIfMatchesRegex(matches, relativePath, fileContents, "inertia.shared_props.sensitive_data", "appears to share sensitive values through Inertia props", inertiaSensitiveSharedPropPattern)
	}

	return matches
}

func looksLikeLivewireComponent(relativePath string, fileContents string) bool {
	if strings.HasPrefix(relativePath, "app/Livewire/") || strings.HasPrefix(relativePath, "app/Http/Livewire/") {
		return true
	}

	if !livewireComponentInheritancePattern.MatchString(fileContents) {
		return false
	}

	return strings.Contains(fileContents, "Livewire\\Component")
}

func looksLikeFilamentFile(relativePath string, fileContents string) bool {
	return strings.HasPrefix(relativePath, "app/Filament/") ||
		strings.Contains(fileContents, "Filament\\") ||
		strings.Contains(relativePath, "Filament")
}

func looksLikeFilamentResourceFile(relativePath string) bool {
	return strings.Contains(relativePath, "/Resources/") || strings.HasSuffix(relativePath, "Resource.php")
}

func looksLikeInertiaFile(relativePath string, fileContents string) bool {
	return relativePath == "app/Http/Middleware/HandleInertiaRequests.php" ||
		strings.Contains(fileContents, "Inertia::share(") ||
		strings.Contains(fileContents, "Inertia\\")
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

func appendSourceMatchIfMatchesRegex(
	matches []model.SourceMatch,
	relativePath string,
	fileContents string,
	ruleID string,
	detail string,
	pattern *regexp.Regexp,
) []model.SourceMatch {
	matchIndexes := pattern.FindStringIndex(fileContents)
	if matchIndexes == nil {
		return matches
	}

	return append(matches, model.SourceMatch{
		RuleID:       ruleID,
		RelativePath: relativePath,
		Line:         lineNumberForOffset(fileContents, matchIndexes[0]),
		Detail:       detail,
	})
}

func appendSourceMatchIfMatchesAnyRegex(
	matches []model.SourceMatch,
	relativePath string,
	fileContents string,
	ruleID string,
	detail string,
	patterns []*regexp.Regexp,
) []model.SourceMatch {
	for _, pattern := range patterns {
		matches = appendSourceMatchIfMatchesRegex(matches, relativePath, fileContents, ruleID, detail, pattern)
		if containsRuleIDAtRelativePath(matches, ruleID, relativePath) {
			return matches
		}
	}

	return matches
}

func containsRuleIDAtRelativePath(matches []model.SourceMatch, ruleID string, relativePath string) bool {
	for _, match := range matches {
		if match.RuleID == ruleID && match.RelativePath == relativePath {
			return true
		}
	}

	return false
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

func stripPHPCommentsPreservingNewlines(fileContents string) string {
	if fileContents == "" {
		return ""
	}

	input := []byte(fileContents)
	output := make([]byte, len(input))
	inSingleQuotedString := false
	inDoubleQuotedString := false
	inLineComment := false
	inBlockComment := false

	for index := 0; index < len(input); index++ {
		currentByte := input[index]
		nextByte := byte(0)
		if index+1 < len(input) {
			nextByte = input[index+1]
		}

		switch {
		case inLineComment:
			if currentByte == '\n' {
				inLineComment = false
				output[index] = '\n'
				continue
			}

			output[index] = ' '
		case inBlockComment:
			if currentByte == '*' && nextByte == '/' {
				output[index] = ' '
				output[index+1] = ' '
				index++
				inBlockComment = false
				continue
			}

			if currentByte == '\n' {
				output[index] = '\n'
				continue
			}

			output[index] = ' '
		case inSingleQuotedString:
			output[index] = currentByte
			if currentByte == '\\' && index+1 < len(input) {
				output[index+1] = input[index+1]
				index++
				continue
			}
			if currentByte == '\'' {
				inSingleQuotedString = false
			}
		case inDoubleQuotedString:
			output[index] = currentByte
			if currentByte == '\\' && index+1 < len(input) {
				output[index+1] = input[index+1]
				index++
				continue
			}
			if currentByte == '"' {
				inDoubleQuotedString = false
			}
		default:
			switch {
			case currentByte == '/' && nextByte == '/':
				output[index] = ' '
				output[index+1] = ' '
				index++
				inLineComment = true
			case currentByte == '/' && nextByte == '*':
				output[index] = ' '
				output[index+1] = ' '
				index++
				inBlockComment = true
			case currentByte == '#' && nextByte != '[':
				output[index] = ' '
				inLineComment = true
			default:
				output[index] = currentByte
				if currentByte == '\'' {
					inSingleQuotedString = true
				}
				if currentByte == '"' {
					inDoubleQuotedString = true
				}
			}
		}
	}

	return string(output)
}
