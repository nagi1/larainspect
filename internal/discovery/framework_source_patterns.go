package discovery

import "regexp"

var frameworkHeuristicOptionalFiles = []string{
	".env.example",
	"app/Http/Middleware/TrustHosts.php",
	"app/Http/Middleware/TrustProxies.php",
	"app/Http/Middleware/VerifyCsrfToken.php",
	"app/Http/Middleware/HandleInertiaRequests.php",
	"bootstrap/app.php",
	"config/app.php",
	"config/auth.php",
	"config/broadcasting.php",
	"config/cors.php",
	"config/database.php",
	"config/fortify.php",
	"config/livewire.php",
	"config/logging.php",
	"config/mail.php",
	"config/session.php",
	"routes/api.php",
	"routes/web.php",
}

var frameworkHeuristicOptionalDirectories = []string{
	"app",
	"app/Filament",
	"app/Http/Livewire",
	"app/Livewire",
	"app/Providers",
	"resources/views",
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
