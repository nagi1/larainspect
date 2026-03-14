package discovery

import (
	"strings"

	"github.com/nagi1/larainspect/internal/model"
)

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

	matches = appendSourceMatchIfContainsAny(matches, relativePath, fileContents, "livewire.component.with_file_uploads", "uses the WithFileUploads trait", []string{"WithFileUploads"})
	matches = appendSourceMatchIfContainsAny(matches, relativePath, fileContents, "livewire.component.upload_validation", "shows upload validation or rules near the component", []string{"validate(", "rules(", "#[Validate"})
	matches = appendLivewireSensitivePropertyMatches(matches, relativePath, fileContents)
	matches = appendSourceMatchIfContainsAny(matches, relativePath, fileContents, "livewire.component.locked_attribute", "shows a Locked attribute on a public property", []string{"#[Locked]", "#[Locked", "Locked]"})
	matches = appendSourceMatchIfContainsAny(matches, relativePath, fileContents, "livewire.component.mutates_model_state", "mutates model state inside the component", []string{"->save(", "->update(", "::create(", "->delete(", "forceDelete("})
	matches = appendSourceMatchIfContainsAny(matches, relativePath, fileContents, "livewire.component.authorizes_action", "shows an authorization call inside the component", []string{"authorize(", "Gate::authorize(", "Gate::allows(", "->can("})

	return matches
}

func appendLivewireSensitivePropertyMatches(matches []model.SourceMatch, relativePath string, fileContents string) []model.SourceMatch {
	propertyMatches := livewireSensitivePublicPropertyPattern.FindAllStringSubmatchIndex(fileContents, -1)
	for _, propertyMatch := range propertyMatches {
		propertyName := fileContents[propertyMatch[2]:propertyMatch[3]]
		if !isLikelySecuritySensitiveLivewireProperty(propertyName) {
			continue
		}

		matches = append(matches, model.SourceMatch{
			RuleID:       "livewire.component.public_sensitive_property",
			RelativePath: relativePath,
			Line:         lineNumberForOffset(fileContents, propertyMatch[0]),
			Detail:       "exposes public property $" + propertyName,
		})
	}

	return matches
}

func detectFilamentFrameworkSourceMatches(relativePath string, fileContents string) []model.SourceMatch {
	if !looksLikeFilamentFile(relativePath, fileContents) {
		return nil
	}

	matches := []model.SourceMatch{{
		RuleID:       "filament.file.detected",
		RelativePath: relativePath,
		Line:         1,
		Detail:       "detected a Filament panel or resource file",
	}}

	if looksLikeFilamentResourceFile(relativePath) {
		matches = append(matches, model.SourceMatch{
			RuleID:       "filament.resource.detected",
			RelativePath: relativePath,
			Line:         1,
			Detail:       "detected a Filament resource file",
		})
	}

	matches = appendSourceMatchIfContainsAny(matches, relativePath, fileContents, "filament.panel.path.admin", "uses the common /admin Filament panel path", []string{"->path('admin')", `->path("admin")`})
	matches = appendSourceMatchIfContainsAny(matches, relativePath, fileContents, "filament.panel.auth_middleware", "shows explicit auth middleware on the Filament panel", []string{"->authMiddleware(", "Authenticate::class"})
	matches = appendSourceMatchIfContainsAny(matches, relativePath, fileContents, "filament.panel.tenant_signal", "shows an explicit tenant hook or tenant middleware", []string{"->tenant(", "->tenantMiddleware(", "HasTenants"})
	matches = appendSourceMatchIfContainsAny(matches, relativePath, fileContents, "filament.panel.mfa_signal", "shows an MFA or two-factor signal near the Filament panel", []string{"twoFactor", "TwoFactor", "mfa", "MFA"})
	matches = appendSourceMatchIfContainsAny(matches, relativePath, fileContents, "filament.resource.policy_signal", "shows a policy or authorization signal in a Filament resource", []string{"canViewAny(", "canEdit(", "canDelete(", "authorize(", "Gate::authorize("})
	matches = appendSourceMatchIfContainsAny(matches, relativePath, fileContents, "filament.resource.tenant_field", "references tenant ownership fields inside Filament resources", []string{"tenant_id", "team_id", "organization_id"})
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

	matches := []model.SourceMatch{{
		RuleID:       "fortify.file.detected",
		RelativePath: relativePath,
		Line:         1,
		Detail:       "detected a Fortify configuration file",
	}}
	matches = appendSourceMatchIfMatchesRegex(matches, relativePath, fileContents, "fortify.feature.registration", "enables the Fortify registration feature", fortifyRegistrationFeaturePattern)
	matches = appendSourceMatchIfMatchesRegex(matches, relativePath, fileContents, "fortify.feature.two_factor", "enables the Fortify two-factor authentication feature", fortifyTwoFactorFeaturePattern)

	return matches
}

func detectInertiaFrameworkSourceMatches(relativePath string, fileContents string) []model.SourceMatch {
	if !looksLikeInertiaFile(relativePath, fileContents) {
		return nil
	}

	matches := []model.SourceMatch{{
		RuleID:       "inertia.file.detected",
		RelativePath: relativePath,
		Line:         1,
		Detail:       "detected an Inertia middleware or shared-props file",
	}}
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
