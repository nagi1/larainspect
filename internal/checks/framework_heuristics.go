package checks

import (
	"context"
	"strings"

	"github.com/nagi1/larainspect/internal/model"
)

const frameworkHeuristicsCheckID = "framework.heuristics"

type FrameworkHeuristicsCheck struct{}

func init() {
	MustRegister(FrameworkHeuristicsCheck{})
}

func (FrameworkHeuristicsCheck) ID() string {
	return frameworkHeuristicsCheckID
}

func (FrameworkHeuristicsCheck) Run(_ context.Context, _ model.ExecutionContext, snapshot model.Snapshot) (model.CheckResult, error) {
	findings := []model.Finding{}

	for _, app := range snapshot.Apps {
		findings = append(findings, buildLaravelFrameworkHeuristicFindings(app)...)
		findings = append(findings, buildLivewireFrameworkHeuristicFindings(app)...)
		findings = append(findings, buildFilamentFrameworkHeuristicFindings(app)...)
		findings = append(findings, buildAdminSurfaceHeuristicFindings(app)...)
	}

	return model.CheckResult{Findings: findings}, nil
}

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

	if sessionSecureCookieMatches := sourceMatchesForRule(app, "laravel.session.secure_cookie_false"); len(sessionSecureCookieMatches) > 0 {
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

func buildLivewireFrameworkHeuristicFindings(app model.LaravelApp) []model.Finding {
	if !appUsesPackage(app, "livewire/livewire") && len(sourceMatchesWithPrefix(app, "livewire.")) == 0 {
		return nil
	}

	findings := []model.Finding{}

	temporaryUploadMatches := sourceMatchesForRule(app, "livewire.temporary_upload.public_disk")
	temporaryUploadMatches = append(temporaryUploadMatches, sourceMatchesForRule(app, "livewire.temporary_upload.public_directory")...)
	if len(temporaryUploadMatches) > 0 {
		findings = append(findings, buildHeuristicFindingForSourceMatches(
			"livewire_temporary_uploads_public",
			app,
			model.SeverityHigh,
			model.ConfidenceProbable,
			"Livewire temporary uploads appear to use a public location",
			"Public temporary upload storage increases the chance that unreviewed files become guessable, exposed, or executable through a weak web boundary.",
			"Move temporary Livewire uploads to a non-public disk or directory and verify upload paths cannot execute PHP or expose untrusted files directly.",
			temporaryUploadMatches,
			nil,
		))
	}

	findings = append(findings, buildLivewireUploadValidationFindings(app)...)
	findings = append(findings, buildLivewireUnlockedPropertyFindings(app)...)
	findings = append(findings, buildLivewireAuthorizationFindings(app)...)

	return findings
}

func buildFilamentFrameworkHeuristicFindings(app model.LaravelApp) []model.Finding {
	if !appUsesPackage(app, "filament/filament") && len(sourceMatchesWithPrefix(app, "filament.")) == 0 {
		return nil
	}

	findings := []model.Finding{}

	panelPathMatches := sourceMatchesForRule(app, "filament.panel.path.admin")
	findings = append(findings, buildFilamentPanelAccessFindings(app, panelPathMatches)...)
	findings = append(findings, buildFilamentPolicySignalFindings(app)...)

	tenantFieldMatches := sourceMatchesForRule(app, "filament.resource.tenant_field")
	tenantSignalMatches := sourceMatchesForRule(app, "filament.panel.tenant_signal")
	if len(tenantFieldMatches) > 0 && len(tenantSignalMatches) == 0 {
		findings = append(findings, buildHeuristicFindingForSourceMatches(
			"filament_tenant_signal_missing",
			app,
			model.SeverityMedium,
			model.ConfidencePossible,
			"Filament resources reference tenant ownership without obvious tenant controls",
			"Tenant identifiers inside admin resources are easy to misuse when panel scoping and authorization are not explicit.",
			"Review tenant scoping, tenant middleware, and policy coverage for Filament resources that expose tenant-owned records.",
			tenantFieldMatches,
			[]model.Evidence{
				{Label: "inference", Detail: "no explicit tenant scoping signal was found in the scanned Filament files"},
			},
		))
	}

	findings = append(findings, buildFilamentMFASignalFindings(app, panelPathMatches)...)

	if sensitiveFieldMatches := sourceMatchesForRule(app, "filament.resource.sensitive_field"); len(sensitiveFieldMatches) > 0 {
		findings = append(findings, buildHeuristicFindingForSourceMatches(
			"filament_sensitive_field_exposure",
			app,
			model.SeverityMedium,
			model.ConfidencePossible,
			"Filament resources appear to expose sensitive model fields",
			"Admin resources that surface password or privilege fields are easy to misuse and deserve deliberate review for visibility and mutation safety.",
			"Review sensitive Filament form and table fields, hide or redact what operators do not need, and require explicit authorization for privileged changes.",
			sensitiveFieldMatches,
			nil,
		))
	}

	return findings
}

func buildLivewireUploadValidationFindings(app model.LaravelApp) []model.Finding {
	findings := []model.Finding{}
	fileUploadMatches := sourceMatchesForRule(app, "livewire.component.with_file_uploads")

	for _, relativePath := range uniqueRelativePathsForMatches(fileUploadMatches) {
		if len(sourceMatchesForRuleAtRelativePath(app, "livewire.component.upload_validation", relativePath)) != 0 {
			continue
		}

		findings = append(findings, buildHeuristicFindingForSourceMatches(
			"livewire_upload_validation_missing_signal",
			app,
			model.SeverityMedium,
			model.ConfidencePossible,
			"Livewire upload component does not show obvious validation rules",
			"File-upload components are easy to under-validate, which can lead to unsafe file types, oversized uploads, or risky storage behavior.",
			"Review each Livewire upload action for MIME, extension, size, and storage validation before trusting it in production.",
			sourceMatchesForRuleAtRelativePath(app, "livewire.component.with_file_uploads", relativePath),
			[]model.Evidence{
				{Label: "inference", Detail: "no validation or rules signal was found in the same scanned Livewire component"},
			},
		))
	}

	return findings
}

func buildLivewireUnlockedPropertyFindings(app model.LaravelApp) []model.Finding {
	findings := []model.Finding{}
	sensitivePropertyMatches := sourceMatchesForRule(app, "livewire.component.public_sensitive_property")

	for _, relativePath := range uniqueRelativePathsForMatches(sensitivePropertyMatches) {
		if len(sourceMatchesForRuleAtRelativePath(app, "livewire.component.locked_attribute", relativePath)) != 0 {
			continue
		}

		findings = append(findings, buildHeuristicFindingForSourceMatches(
			"livewire_sensitive_public_property_unlocked",
			app,
			model.SeverityMedium,
			model.ConfidencePossible,
			"Livewire component exposes security-sensitive public properties without obvious locking",
			"Mutable public properties such as tenant, role, or user identifiers are common tampering targets when component state crosses trust boundaries.",
			"Review sensitive public properties, add Locked attributes where appropriate, and avoid trusting client-controlled identifiers without server-side authorization.",
			sourceMatchesForRuleAtRelativePath(app, "livewire.component.public_sensitive_property", relativePath),
			[]model.Evidence{
				{Label: "inference", Detail: "no Locked attribute signal was found in the scanned component"},
			},
		))
	}

	return findings
}

func buildLivewireAuthorizationFindings(app model.LaravelApp) []model.Finding {
	findings := []model.Finding{}
	mutatingComponentMatches := sourceMatchesForRule(app, "livewire.component.mutates_model_state")

	for _, relativePath := range uniqueRelativePathsForMatches(mutatingComponentMatches) {
		if len(sourceMatchesForRuleAtRelativePath(app, "livewire.component.authorizes_action", relativePath)) != 0 {
			continue
		}

		findings = append(findings, buildHeuristicFindingForSourceMatches(
			"livewire_mutation_without_authorization_signal",
			app,
			model.SeverityMedium,
			model.ConfidencePossible,
			"Livewire component mutates model state without obvious authorization checks",
			"State-changing Livewire actions can become privilege-escalation or tenant-breakout paths when authorization lives only in front-end assumptions.",
			"Review mutating Livewire actions and add explicit policy or gate checks close to the write operation.",
			sourceMatchesForRuleAtRelativePath(app, "livewire.component.mutates_model_state", relativePath),
			[]model.Evidence{
				{Label: "inference", Detail: "no authorize or Gate signal was found in the scanned component"},
			},
		))
	}

	return findings
}

func buildFilamentPanelAccessFindings(app model.LaravelApp, panelPathMatches []model.SourceMatch) []model.Finding {
	findings := []model.Finding{}

	for _, relativePath := range uniqueRelativePathsForMatches(panelPathMatches) {
		if len(sourceMatchesForRuleAtRelativePath(app, "filament.panel.auth_middleware", relativePath)) != 0 {
			continue
		}

		findings = append(findings, buildHeuristicFindingForSourceMatches(
			"filament_panel_public_admin_path",
			app,
			model.SeverityHigh,
			model.ConfidenceProbable,
			"Filament panel appears to use a public /admin path without obvious extra auth middleware",
			"Admin surfaces on common paths attract enumeration, brute-force, and credential-stuffing attempts and usually need tighter controls than default route groups.",
			"Review the Filament panel path, add explicit auth middleware and access restrictions, and verify production-only guards such as MFA where supported.",
			sourceMatchesForRuleAtRelativePath(app, "filament.panel.path.admin", relativePath),
			[]model.Evidence{
				{Label: "inference", Detail: "no explicit Filament auth middleware signal was found in the same scanned panel file"},
			},
		))
	}

	return findings
}

func buildFilamentPolicySignalFindings(app model.LaravelApp) []model.Finding {
	findings := []model.Finding{}
	resourceMatches := sourceMatchesForRule(app, "filament.resource.detected")

	for _, relativePath := range uniqueRelativePathsForMatches(resourceMatches) {
		if len(sourceMatchesForRuleAtRelativePath(app, "filament.resource.policy_signal", relativePath)) != 0 {
			continue
		}

		findings = append(findings, buildHeuristicFindingForSourceMatches(
			"filament_policy_signal_missing",
			app,
			model.SeverityMedium,
			model.ConfidencePossible,
			"Filament resources do not show obvious policy signals",
			"Filament panels often wrap high-value data and admin actions, so weak or implicit authorization patterns are easy to miss during review.",
			"Verify Filament resources and pages enforce policies or gates intentionally, even if the enforcement lives outside the resource class.",
			sourceMatchesForRuleAtRelativePath(app, "filament.resource.detected", relativePath),
			[]model.Evidence{
				{Label: "inference", Detail: "no obvious policy or authorization signal was found in the same scanned Filament resource"},
			},
		))
	}

	return findings
}

func buildFilamentMFASignalFindings(app model.LaravelApp, panelPathMatches []model.SourceMatch) []model.Finding {
	findings := []model.Finding{}

	for _, relativePath := range uniqueRelativePathsForMatches(panelPathMatches) {
		if len(sourceMatchesForRuleAtRelativePath(app, "filament.panel.mfa_signal", relativePath)) != 0 {
			continue
		}

		findings = append(findings, buildHeuristicFindingForSourceMatches(
			"filament_mfa_signal_missing",
			app,
			model.SeverityLow,
			model.ConfidencePossible,
			"Filament admin surface does not show obvious MFA-related signals",
			"Admin panels often hold credential, user-management, and high-privilege actions that benefit from stronger authentication controls.",
			"Confirm the production admin flow uses MFA or an equivalent second-factor control where the chosen auth stack supports it.",
			sourceMatchesForRuleAtRelativePath(app, "filament.panel.path.admin", relativePath),
			[]model.Evidence{
				{Label: "inference", Detail: "no MFA or two-factor signal was found in the same scanned Filament panel file"},
			},
		))
	}

	return findings
}

func buildAdminSurfaceHeuristicFindings(app model.LaravelApp) []model.Finding {
	findings := []model.Finding{}

	for _, packageExposureDefinition := range riskyPackageExposureDefinitions() {
		packageFinding, found := buildRiskyPackageExposureFinding(app, packageExposureDefinition)
		if !found {
			continue
		}

		findings = append(findings, packageFinding)
	}

	publicAdminToolArtifacts := []model.ArtifactRecord{}
	for _, artifact := range app.Artifacts {
		if artifact.Kind == model.ArtifactKindPublicAdminTool && artifact.WithinPublicPath {
			publicAdminToolArtifacts = append(publicAdminToolArtifacts, artifact)
		}
	}
	if len(publicAdminToolArtifacts) > 0 {
		findings = append(findings, buildHeuristicFindingForPublicAdminToolArtifacts(app, publicAdminToolArtifacts))
	}

	return findings
}

type riskyPackageExposureDefinition struct {
	PackageName       string
	Title             string
	Why               string
	Remediation       string
	HighWhenInstalled bool
}

func riskyPackageExposureDefinitions() []riskyPackageExposureDefinition {
	return []riskyPackageExposureDefinition{
		{
			PackageName:       "laravel/telescope",
			Title:             "Laravel Telescope package appears present",
			Why:               "Telescope can expose requests, queries, jobs, exceptions, and environment details if it is reachable or weakly gated in production.",
			Remediation:       "Verify Telescope is disabled or tightly gated in production and confirm the dashboard is not reachable without strong operator controls.",
			HighWhenInstalled: true,
		},
		{
			PackageName: "barryvdh/laravel-debugbar",
			Title:       "Laravel Debugbar package appears present",
			Why:         "Debugbar can expose SQL, timing, route, and exception details that help attackers understand the application internals.",
			Remediation: "Keep Debugbar out of production builds or prove it is disabled and unreachable in the deployed runtime.",
		},
		{
			PackageName: "itsgoingd/clockwork",
			Title:       "Clockwork package appears present",
			Why:         "Clockwork can expose request timelines, configuration clues, and debugging detail when it remains reachable on production hosts.",
			Remediation: "Verify Clockwork is not exposed in production and keep its routes or headers tightly restricted when used for diagnostics.",
		},
		{
			PackageName: "spatie/laravel-ignition",
			Title:       "Ignition package appears present",
			Why:         "Ignition and related error tooling can expose stack traces, config clues, and exception context when production hardening is incomplete.",
			Remediation: "Verify the production error handler does not expose Ignition debug surfaces and keep detailed exception tooling out of public reach.",
		},
	}
}

func buildRiskyPackageExposureFinding(app model.LaravelApp, definition riskyPackageExposureDefinition) (model.Finding, bool) {
	packageRecord, found := packageRecordForApp(app, definition.PackageName)
	if !found {
		return model.Finding{}, false
	}

	severity, confidence := packageExposureSeverityAndConfidence(packageRecord, definition.HighWhenInstalled)

	return buildHeuristicFindingForPackageRecord(
		definition.PackageName,
		app,
		packageRecord,
		severity,
		confidence,
		definition.Title,
		definition.Why,
		definition.Remediation,
	), true
}

func packageExposureSeverityAndConfidence(packageRecord model.PackageRecord, highWhenInstalled bool) (model.Severity, model.Confidence) {
	if packageRecordComesFromInstalledMetadata(packageRecord) {
		if highWhenInstalled {
			return model.SeverityHigh, model.ConfidenceProbable
		}

		return model.SeverityMedium, model.ConfidenceProbable
	}

	if highWhenInstalled {
		return model.SeverityMedium, model.ConfidencePossible
	}

	return model.SeverityLow, model.ConfidencePossible
}

func packageRecordComesFromInstalledMetadata(packageRecord model.PackageRecord) bool {
	switch packageRecord.Source {
	case "composer.lock", "vendor/composer/installed.json":
		return true
	default:
		return false
	}
}

func buildHeuristicFindingForSourceMatches(
	suffix string,
	app model.LaravelApp,
	severity model.Severity,
	confidence model.Confidence,
	title string,
	why string,
	remediation string,
	sourceMatches []model.SourceMatch,
	additionalEvidence []model.Evidence,
) model.Finding {
	evidence := []model.Evidence{}
	affected := []model.Target{appTarget(app)}
	seenAffectedPaths := map[string]struct{}{
		app.RootPath: {},
	}

	for _, sourceMatch := range sourceMatches {
		evidence = append(evidence, sourceMatchEvidence(app, sourceMatch)...)

		target := sourceMatchTarget(app, sourceMatch)
		if _, seen := seenAffectedPaths[target.Path]; seen {
			continue
		}
		seenAffectedPaths[target.Path] = struct{}{}
		affected = append(affected, target)
	}

	evidence = append(evidence, additionalEvidence...)

	return model.Finding{
		ID:          buildFindingID(frameworkHeuristicsCheckID, suffix, app.RootPath),
		CheckID:     frameworkHeuristicsCheckID,
		Class:       model.FindingClassHeuristic,
		Severity:    severity,
		Confidence:  confidence,
		Title:       title,
		Why:         why,
		Remediation: remediation,
		Evidence:    evidence,
		Affected:    affected,
	}
}

func buildHeuristicFindingForPackageRecord(
	packageName string,
	app model.LaravelApp,
	packageRecord model.PackageRecord,
	severity model.Severity,
	confidence model.Confidence,
	title string,
	why string,
	remediation string,
) model.Finding {
	return model.Finding{
		ID:          buildFindingID(frameworkHeuristicsCheckID, "package."+strings.ReplaceAll(packageName, "/", "."), app.RootPath),
		CheckID:     frameworkHeuristicsCheckID,
		Class:       model.FindingClassHeuristic,
		Severity:    severity,
		Confidence:  confidence,
		Title:       title,
		Why:         why,
		Remediation: remediation,
		Evidence: []model.Evidence{
			{Label: "package", Detail: packageRecord.Name},
			{Label: "version", Detail: firstNonEmpty(packageRecord.Version, "unknown")},
			{Label: "source", Detail: packageRecord.Source},
			{Label: "inference", Detail: packageExposureInferenceDetail(packageRecord)},
		},
		Affected: []model.Target{
			appTarget(app),
		},
	}
}

func buildHeuristicFindingForPublicAdminToolArtifacts(app model.LaravelApp, artifacts []model.ArtifactRecord) model.Finding {
	evidence := []model.Evidence{}
	affected := []model.Target{appTarget(app)}

	for _, artifact := range artifacts {
		evidence = append(evidence, pathEvidence(artifact.Path)...)
		affected = append(affected, pathTarget(artifact.Path))
	}

	return model.Finding{
		ID:          buildFindingID(frameworkHeuristicsCheckID, "public_admin_tool", app.RootPath),
		CheckID:     frameworkHeuristicsCheckID,
		Class:       model.FindingClassHeuristic,
		Severity:    model.SeverityHigh,
		Confidence:  model.ConfidenceProbable,
		Title:       "Public path contains diagnostic or admin tooling",
		Why:         "Adminer, phpMyAdmin, phpinfo, and similar tools materially expand an attack surface when they remain inside a served path.",
		Remediation: "Remove diagnostic and database-admin tools from the public tree or place them behind tightly controlled, temporary operational access.",
		Evidence:    evidence,
		Affected:    affected,
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}

	return ""
}

func packageExposureInferenceDetail(packageRecord model.PackageRecord) string {
	if packageRecordComesFromInstalledMetadata(packageRecord) {
		return "package appears installed in composer metadata and should be reviewed for production exposure"
	}

	return "package is declared in composer metadata but installation or runtime exposure was not confirmed from the available snapshot"
}
