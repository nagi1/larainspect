package discovery

import (
	"regexp"

	"github.com/nagi1/larainspect/internal/model"
)

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
