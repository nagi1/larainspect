package checks

import "github.com/nagi1/larainspect/internal/model"

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
