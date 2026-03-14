package checks

import "github.com/nagi1/larainspect/internal/model"

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
