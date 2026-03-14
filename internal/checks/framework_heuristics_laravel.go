package checks

import "github.com/nagi1/larainspect/internal/model"

func buildLaravelFrameworkHeuristicFindings(app model.LaravelApp) []model.Finding {
	findings := []model.Finding{}

	if csrfWildcardMatches := sourceMatchesForRule(app, "laravel.csrf.except_all"); len(csrfWildcardMatches) > 0 {
		findings = append(findings, buildHeuristicFindingForSourceMatches(
			"csrf_except_all",
			app,
			model.SeverityHigh,
			model.ConfidenceProbable,
			"CSRF exclusions appear to cover nearly all routes",
			"Broad CSRF exclusions weaken one of Laravel's core browser-session protections and can expose state-changing routes to cross-site request abuse.",
			"Limit CSRF exclusions to the exact webhook or callback endpoints that need them and document why each exclusion is required.",
			csrfWildcardMatches,
			nil,
		))
	}

	if trustProxyWildcardMatches := sourceMatchesForRule(app, "laravel.trusted_proxies.wildcard"); len(trustProxyWildcardMatches) > 0 {
		findings = append(findings, buildHeuristicFindingForSourceMatches(
			"trusted_proxies_wildcard",
			app,
			model.SeverityMedium,
			model.ConfidenceProbable,
			"Trusted proxy configuration appears to trust all proxies",
			"Wildcard trusted-proxy settings can let attacker-controlled forwarding headers influence client IP, scheme, and rate-limit decisions.",
			"Restrict trusted proxies to the exact reverse proxies or load balancers that actually forward requests for this app.",
			trustProxyWildcardMatches,
			nil,
		))
	}

	if trustHostsWildcardMatches := sourceMatchesForRule(app, "laravel.trusted_hosts.wildcard"); len(trustHostsWildcardMatches) > 0 {
		findings = append(findings, buildHeuristicFindingForSourceMatches(
			"trusted_hosts_wildcard",
			app,
			model.SeverityMedium,
			model.ConfidenceProbable,
			"Trusted hosts configuration appears to allow all hosts",
			"An all-host allowlist weakens host-header protections and makes accidental or malicious alternate hostnames harder to contain.",
			"Constrain trusted hosts to the production domains that should route to this Laravel app.",
			trustHostsWildcardMatches,
			nil,
		))
	}

	if sessionSecureCookieMatches := sourceMatchesForRule(app, "laravel.session.secure_cookie_false"); len(sessionSecureCookieMatches) > 0 && !appHasSecureSessionCookieRuntimeOverride(app) {
		findings = append(findings, buildHeuristicFindingForSourceMatches(
			"session_secure_cookie_default",
			app,
			model.SeverityLow,
			model.ConfidencePossible,
			"Session config does not show an obvious secure-cookie default",
			"If session cookies are allowed over non-HTTPS transport, admin and operator sessions are easier to steal on misconfigured or downgraded paths.",
			"Set the session secure-cookie default explicitly for production and verify the effective runtime value after config caching.",
			sessionSecureCookieMatches,
			nil,
		))
	}

	adminRouteMatches := sourceMatchesForRule(app, "laravel.route.admin_path")
	authMiddlewareMatches := sourceMatchesForRule(app, "laravel.route.auth_middleware")
	if len(adminRouteMatches) > 0 && len(authMiddlewareMatches) == 0 {
		findings = append(findings, buildHeuristicFindingForSourceMatches(
			"admin_route_without_auth_signal",
			app,
			model.SeverityHigh,
			model.ConfidenceProbable,
			"Admin-like routes do not show obvious auth middleware",
			"Admin routes without clear auth middleware are easy to expose by mistake and usually deserve stronger controls than ordinary web routes.",
			"Review admin route groups and add explicit auth middleware, authorization gates, and access restrictions where appropriate.",
			adminRouteMatches,
			[]model.Evidence{
				{Label: "inference", Detail: "no explicit auth middleware signal was found in the scanned route files"},
			},
		))
	}

	loginRouteMatches := sourceMatchesForRule(app, "laravel.route.login_path")
	throttleMiddlewareMatches := sourceMatchesForRule(app, "laravel.route.throttle_middleware")
	if (len(adminRouteMatches) > 0 || len(loginRouteMatches) > 0) && len(throttleMiddlewareMatches) == 0 {
		matches := append([]model.SourceMatch{}, adminRouteMatches...)
		matches = append(matches, loginRouteMatches...)
		findings = append(findings, buildHeuristicFindingForSourceMatches(
			"route_without_throttle_signal",
			app,
			model.SeverityMedium,
			model.ConfidencePossible,
			"Custom login or admin routes do not show obvious throttling",
			"Sensitive route groups usually need explicit throttling to slow brute-force and credential-stuffing attempts.",
			"Add explicit throttle middleware to custom login and admin route groups and verify the intended rate limits in production.",
			matches,
			[]model.Evidence{
				{Label: "inference", Detail: "no throttle middleware signal was found in the scanned route files"},
			},
		))
	}

	if apiAdminMatches := sourceMatchesForRule(app, "laravel.route.api_admin_path"); len(apiAdminMatches) > 0 {
		findings = append(findings, buildHeuristicFindingForSourceMatches(
			"admin_routes_in_api_file",
			app,
			model.SeverityMedium,
			model.ConfidenceProbable,
			"Admin-like endpoints appear inside routes/api.php",
			"Blending browser-admin and API routes increases the chance of missing session, CSRF, or guard assumptions when the app evolves.",
			"Keep admin surfaces clearly separated from API route groups and verify the exact guard, middleware, and session model intended for each surface.",
			apiAdminMatches,
			nil,
		))
	}

	return findings
}

func buildFortifyFrameworkHeuristicFindings(app model.LaravelApp) []model.Finding {
	if !appUsesPackage(app, "laravel/fortify") && len(sourceMatchesWithPrefix(app, "fortify.")) == 0 {
		return nil
	}

	if registrationMatches := sourceMatchesForRule(app, "fortify.feature.registration"); len(registrationMatches) > 0 {
		return []model.Finding{buildHeuristicFindingForSourceMatches(
			"fortify_registration_enabled",
			app,
			model.SeverityMedium,
			model.ConfidenceProbable,
			"Fortify self-registration appears enabled",
			"Public self-registration expands the authentication surface and usually needs deliberate review for abuse controls, onboarding policy, and account verification.",
			"Confirm self-registration is intentionally public, require appropriate verification or approval steps, and disable the feature where accounts should be provisioned centrally.",
			registrationMatches,
			nil,
		)}
	}

	return nil
}

func buildInertiaFrameworkHeuristicFindings(app model.LaravelApp) []model.Finding {
	if !appUsesPackage(app, "inertiajs/inertia-laravel") && len(sourceMatchesWithPrefix(app, "inertia.")) == 0 {
		return nil
	}

	if sensitiveSharedPropMatches := sourceMatchesForRule(app, "inertia.shared_props.sensitive_data"); len(sensitiveSharedPropMatches) > 0 {
		return []model.Finding{buildHeuristicFindingForSourceMatches(
			"inertia_sensitive_shared_props",
			app,
			model.SeverityHigh,
			model.ConfidenceProbable,
			"Inertia shared props appear to expose sensitive values",
			"Shared Inertia props are delivered broadly to client-side pages, so secrets, tokens, and privileged values can leak beyond the server-side trust boundary quickly.",
			"Remove sensitive values from shared props, derive only the minimum safe client state, and keep secrets or bearer-style tokens on the server side.",
			sensitiveSharedPropMatches,
			nil,
		)}
	}

	return nil
}
