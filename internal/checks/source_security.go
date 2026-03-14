package checks

import (
	"context"
	"strings"

	"github.com/nagi1/larainspect/internal/model"
)

const sourceSecurityCheckID = "source.security"

var _ Check = SourceSecurityCheck{}

type SourceSecurityCheck struct{}

func init() {
	MustRegister(SourceSecurityCheck{})
}

func (SourceSecurityCheck) ID() string {
	return sourceSecurityCheckID
}

func (SourceSecurityCheck) Description() string {
	return "Inspect Laravel source for high-signal Ward-inspired security patterns."
}

func (SourceSecurityCheck) Run(_ context.Context, _ model.ExecutionContext, snapshot model.Snapshot) (model.CheckResult, error) {
	findings := []model.Finding{}

	for _, app := range snapshot.Apps {
		findings = append(findings, appendRuleSecurityFinding(snapshot, app,
			model.FindingClassHeuristic,
			"login_using_id_variable",
			"laravel.auth.login_using_id_variable",
			model.SeverityHigh, model.ConfidencePossible,
			"Code logs users in without a password from variable input",
			"loginUsingId() skips password verification. If the user ID comes from a request, token, or query result that is not fully trusted, someone may be signed in as the wrong user.",
			"Use normal authentication for user-driven login. Keep loginUsingId() only for tightly controlled internal flows, and validate and document exactly where the user ID comes from.",
			nil,
		)...)
		findings = append(findings, appendRuleSecurityFinding(snapshot, app,
			model.FindingClassHeuristic,
			"mass_assignment_guarded_all",
			"laravel.security.mass_assignment.guarded_all",
			model.SeverityHigh, model.ConfidenceProbable,
			"Model uses an empty $guarded list",
			"Setting $guarded = [] makes every attribute mass assignable and increases the chance that privilege or ownership fields can be written unintentionally through request-driven create or update flows.",
			"Prefer explicit $fillable fields or at least guard privilege-sensitive attributes such as role, is_admin, and tenant ownership fields.",
			nil,
		)...)
		findings = append(findings, appendRuleSecurityFinding(snapshot, app,
			model.FindingClassDirect,
			"upload_executable_mimes",
			"laravel.security.upload.executable_mimes",
			model.SeverityCritical, model.ConfidenceProbable,
			"File upload rules allow server-executable files",
			"If users can upload files such as php, phtml, or phar and those files land in a reachable web path, the server may run attacker-controlled code.",
			"Allow only known-safe upload types, store uploads outside executable web paths, and block PHP execution in upload and storage directories.",
			nil,
		)...)
		findings = append(findings, appendRuleSecurityFinding(snapshot, app,
			model.FindingClassDirect,
			"upload_risky_web_types",
			"laravel.security.upload.risky_web_types",
			model.SeverityHigh, model.ConfidenceProbable,
			"File upload rules allow HTML or SVG files",
			"HTML and SVG files can run scripts in the browser. If these uploads are served back to users, they can steal sessions, deface pages, or impersonate your app.",
			"Prefer non-active file types for uploads. If HTML or SVG is required, sanitize the content, force safe download headers where possible, and keep it out of public execution paths.",
			nil,
		)...)
		findings = append(findings, appendRuleSecurityFinding(snapshot, app,
			model.FindingClassHeuristic,
			"upload_file_without_constraints",
			"laravel.security.upload.file_without_constraints",
			model.SeverityMedium, model.ConfidencePossible,
			"Upload validation shows a file rule without obvious type or size constraints",
			"A plain file validation rule without nearby type or size restrictions is easy to under-harden and can allow unsafe formats, oversized payloads, or policy drift over time.",
			"Add explicit size and type constraints such as mimes, mimetypes, image, or max near every upload validation rule before trusting the upload path in production.",
			nil,
		)...)
		if uploadExposureFinding, found := buildPublicUploadExposureCorrelationFinding(app, snapshot); found {
			findings = append(findings, uploadExposureFinding)
		}
		findings = append(findings, appendRuleSecurityFinding(snapshot, app,
			model.FindingClassDirect,
			"phpinfo_call",
			"laravel.debug.phpinfo_call",
			model.SeverityHigh, model.ConfidenceProbable,
			"Source contains phpinfo()",
			"phpinfo() exposes PHP runtime details, loaded modules, paths, and environment information that help attackers profile a target quickly.",
			"Remove phpinfo() from deployed code or keep it behind short-lived, tightly controlled operational access that never reaches public routes.",
			nil,
		)...)
		findings = append(findings, appendRuleSecurityFinding(snapshot, app,
			model.FindingClassDirect,
			"dd_call",
			"laravel.debug.dd_call",
			model.SeverityHigh, model.ConfidenceProbable,
			"Source contains dd()",
			"dd() stops execution and can dump sensitive runtime data directly into responses, which creates both availability and disclosure risk when left in reachable code.",
			"Remove dd() from deployed code and use structured logging or environment-gated diagnostics instead.",
			nil,
		)...)

		dumpSeverity, dumpConfidence, dumpTitle, dumpWhy, dumpRemediation := ruleMetadata(
			snapshot, "laravel.debug.dump_call",
			model.SeverityMedium, model.ConfidencePossible,
			"Source contains debug output helpers",
			"dump(), var_dump(), print_r(), var_export(), and Blade dump directives often leak internal state into responses when code paths stay reachable after development.",
			"Remove debug output from deployed code paths and keep diagnostics in logs or dedicated developer tooling.",
		)
		findings = append(findings, appendSourceSecurityFinding(app,
			model.FindingClassHeuristic,
			"dump_calls",
			dumpSeverity, dumpConfidence,
			dumpTitle, dumpWhy, dumpRemediation,
			appendSourceMatches(
				sourceMatchesForRule(app, "laravel.debug.dump_call"),
				sourceMatchesForRule(app, "laravel.debug.var_dump_call"),
				sourceMatchesForRule(app, "laravel.debug.blade_dump_directive"),
			),
			nil,
		)...)

		findings = append(findings, appendRuleSecurityFinding(snapshot, app,
			model.FindingClassDirect,
			"blade_raw_request",
			"laravel.xss.blade_raw_request",
			model.SeverityHigh, model.ConfidenceProbable,
			"Blade template renders request data through raw output",
			"Rendering request-derived values through raw Blade output bypasses Laravel's normal HTML escaping and creates an obvious stored or reflected XSS path.",
			"Replace raw Blade output with escaped output and only render HTML after explicit sanitization.",
			nil,
		)...)
		findings = append(findings, appendRuleSecurityFinding(snapshot, app,
			model.FindingClassHeuristic,
			"blade_raw_variable",
			"laravel.xss.blade_raw_variable",
			model.SeverityMedium, model.ConfidencePossible,
			"Blade template renders a variable through raw output",
			"Raw Blade output is not always exploitable, but it becomes an XSS sink quickly when request, model, or CMS content reaches the template unsanitized.",
			"Prefer escaped Blade output by default and document the sanitization path for any value intentionally rendered as raw HTML.",
			nil,
		)...)
		findings = append(findings, appendRuleSecurityFinding(snapshot, app,
			model.FindingClassHeuristic,
			"script_variable_interpolation",
			"laravel.xss.script_variable_interpolation",
			model.SeverityMedium, model.ConfidencePossible,
			"Blade template interpolates a PHP variable inside a script block",
			"Injecting Blade variables directly into JavaScript without JSON encoding can turn harmless data into executable script context when special characters are present.",
			"Use @json or another explicit encoder when server values need to cross into JavaScript.",
			nil,
		)...)
		findings = append(findings, appendRuleSecurityFinding(snapshot, app,
			model.FindingClassHeuristic,
			"db_raw_variable",
			"laravel.inject.db_raw_variable",
			model.SeverityHigh, model.ConfidencePossible,
			"Raw SQL fragment is built from variable input",
			"When SQL text is built from variables instead of parameters, attacker-controlled input can change the query and read or modify data unexpectedly.",
			"Use Laravel query builder methods or bound parameters so values stay separate from the SQL statement.",
			nil,
		)...)
		findings = append(findings, appendRuleSecurityFinding(snapshot, app,
			model.FindingClassHeuristic,
			"raw_query_variable",
			"laravel.inject.raw_query_variable",
			model.SeverityHigh, model.ConfidencePossible,
			"Raw SQL query text is built from variable input",
			"Building SQL from variables instead of parameters makes it much easier for untrusted input to change the query unexpectedly.",
			"Use bound parameters or non-raw query builder operations instead of assembling SQL fragments from variables.",
			nil,
		)...)
		findings = append(findings, appendRuleSecurityFinding(snapshot, app,
			model.FindingClassHeuristic,
			"direct_sql_concat",
			"laravel.inject.direct_sql_concat",
			model.SeverityCritical, model.ConfidencePossible,
			"Direct SQL statement is assembled with string concatenation",
			"Building DB::select, DB::update, DB::delete, or DB::statement queries by concatenating variables is a strong sign of SQL injection risk, because input becomes part of the SQL command itself.",
			"Replace string-built SQL with parameterized queries or higher-level Laravel query builder calls.",
			nil,
		)...)
		findings = append(findings, appendRuleSecurityFinding(snapshot, app,
			model.FindingClassHeuristic,
			"shell_exec",
			"laravel.inject.shell_exec",
			model.SeverityHigh, model.ConfidencePossible,
			"Code runs shell commands with application input",
			"Shell commands become dangerous quickly when any part of the command includes user-controlled or loosely validated data, because the server may execute unintended commands.",
			"Prefer library or framework APIs instead of shelling out. If a shell command is unavoidable, keep the command fixed and validate each argument against a strict allowlist.",
			nil,
		)...)
		findings = append(findings, appendRuleSecurityFinding(snapshot, app,
			model.FindingClassHeuristic,
			"eval_usage",
			"laravel.inject.eval",
			model.SeverityCritical, model.ConfidenceProbable,
			"Code executes dynamic PHP with eval()",
			"eval() runs PHP built from a string. Any bug that lets outside data reach that string can turn into full code execution.",
			"Remove eval(). Replace it with normal conditionals, a lookup table, templates, or another explicit code path that does not execute generated PHP.",
			nil,
		)...)
		findings = append(findings, appendRuleSecurityFinding(snapshot, app,
			model.FindingClassHeuristic,
			"unserialize_variable",
			"laravel.inject.unserialize_variable",
			model.SeverityHigh, model.ConfidencePossible,
			"Code unserializes data from a variable",
			"If serialized data can be influenced by a user or another untrusted source, unserialize() can trigger unsafe object behavior and lead to code or state manipulation.",
			"Prefer JSON for exchanged data. If serialized PHP data is unavoidable, accept it only from trusted sources and strictly limit allowed classes.",
			nil,
		)...)
	}

	return model.CheckResult{Findings: findings}, nil
}

// appendRuleSecurityFinding resolves metadata from the YAML rule definition
// (honoring config overrides) and falls back to the provided defaults.
func appendRuleSecurityFinding(
	snapshot model.Snapshot,
	app model.LaravelApp,
	class model.FindingClass,
	suffix string,
	ruleID string,
	fallbackSeverity model.Severity,
	fallbackConfidence model.Confidence,
	fallbackTitle string,
	fallbackWhy string,
	fallbackRemediation string,
	additionalEvidence []model.Evidence,
) []model.Finding {
	matches := sourceMatchesForRule(app, ruleID)
	if len(matches) == 0 {
		return nil
	}

	severity, confidence, title, why, remediation := ruleMetadata(
		snapshot, ruleID,
		fallbackSeverity, fallbackConfidence, fallbackTitle, fallbackWhy, fallbackRemediation,
	)

	return []model.Finding{buildSourceFinding(
		sourceSecurityCheckID, suffix, app, class,
		severity, confidence, title, why, remediation,
		matches, additionalEvidence,
	)}
}

func appendSourceSecurityFinding(
	app model.LaravelApp,
	class model.FindingClass,
	suffix string,
	severity model.Severity,
	confidence model.Confidence,
	title string,
	why string,
	remediation string,
	sourceMatches []model.SourceMatch,
	additionalEvidence []model.Evidence,
) []model.Finding {
	if len(sourceMatches) == 0 {
		return nil
	}

	return []model.Finding{buildSourceFinding(
		sourceSecurityCheckID, suffix, app, class,
		severity, confidence, title, why, remediation,
		sourceMatches, additionalEvidence,
	)}
}

func buildPublicUploadExposureCorrelationFinding(app model.LaravelApp, snapshot model.Snapshot) (model.Finding, bool) {
	publicStoragePath, found := appExpectedPublicStorageSymlink(app)
	if !found {
		return model.Finding{}, false
	}

	sourceMatches := uploadExposureSourceMatches(app)
	if len(sourceMatches) == 0 {
		return model.Finding{}, false
	}

	matchedSites := nginxSitesForApp(app, snapshot.NginxSites)
	publicPHPArtifacts := publicUploadPHPArtifacts(app)
	if len(matchedSites) == 0 && len(publicPHPArtifacts) == 0 {
		return model.Finding{}, false
	}

	evidence := []model.Evidence{}
	affected := []model.Target{
		appTarget(app),
		pathTarget(publicStoragePath),
	}
	seenAffected := map[string]struct{}{
		app.RootPath:                   {},
		publicStoragePath.AbsolutePath: {},
	}

	for _, sourceMatch := range sourceMatches {
		evidence = append(evidence, sourceMatchEvidence(app, sourceMatch)...)
		target := sourceMatchTarget(app, sourceMatch)
		affected, seenAffected = appendUniqueTarget(affected, seenAffected, target)
	}

	evidence = append(evidence, pathEvidence(publicStoragePath)...)
	evidence = append(evidence, model.Evidence{
		Label:  "exposure",
		Detail: "Files written to the Laravel public disk become web-reachable under /storage/... through public/storage.",
	})

	highestSeverity := model.SeverityMedium
	confidence := model.ConfidencePossible

	if hasActiveWebUploadGap(app) {
		highestSeverity = model.SeverityHigh
	}

	for _, artifact := range publicPHPArtifacts {
		evidence = append(evidence, pathEvidence(artifact.Path)...)
		affected, seenAffected = appendUniqueTarget(affected, seenAffected, pathTarget(artifact.Path))
	}
	if len(publicPHPArtifacts) > 0 {
		highestSeverity = model.SeverityHigh
		confidence = model.ConfidenceProbable
		evidence = append(evidence, model.Evidence{
			Label:  "artifact",
			Detail: "Upload-like public paths already contain PHP files.",
		})
	}

	if len(matchedSites) > 0 {
		confidence = model.ConfidenceProbable
		configPaths, phpBoundaryNotes := summarizeUploadBoundarySites(matchedSites)
		for _, site := range matchedSites {
			affected, seenAffected = appendUniqueTarget(affected, seenAffected, model.Target{Type: "path", Path: site.ConfigPath})
		}
		evidence = append(evidence, model.Evidence{Label: "config", Detail: strings.Join(configPaths, ", ")})
		if phpBoundaryNotes != "" {
			evidence = append(evidence, model.Evidence{Label: "php_boundary", Detail: phpBoundaryNotes})
			highestSeverity = model.SeverityHigh
		}
	}

	return model.Finding{
		ID:          buildFindingID(sourceSecurityCheckID, "public_upload_exposure_alignment", app.RootPath),
		CheckID:     sourceSecurityCheckID,
		Class:       model.FindingClassHeuristic,
		Severity:    highestSeverity,
		Confidence:  confidence,
		Title:       "Upload validation gaps align with Laravel public storage exposure",
		Why:         "When public/storage is active, files written to the public disk become web-reachable under /storage/..., so weak type controls or active web content allowances increase the chance that untrusted uploads become public XSS, phishing, or execution-adjacent exposure paths.",
		Remediation: "Keep untrusted uploads off the public disk where possible, require stronger controls than a single extension or MIME allowlist for active web content, and verify Nginx blocks PHP from public/storage and upload-like paths.",
		Evidence:    evidence,
		Affected:    affected,
	}, true
}

func uploadExposureSourceMatches(app model.LaravelApp) []model.SourceMatch {
	return appendSourceMatches(
		sourceMatchesForRule(app, "laravel.security.upload.file_without_constraints"),
		sourceMatchesForRule(app, "laravel.security.upload.risky_web_types"),
		sourceMatchesForRule(app, "laravel.security.upload.risky_web_types_extension_only"),
		sourceMatchesForRule(app, "laravel.security.upload.risky_web_types_mime_only"),
	)
}

func hasActiveWebUploadGap(app model.LaravelApp) bool {
	return len(appendSourceMatches(
		sourceMatchesForRule(app, "laravel.security.upload.risky_web_types"),
		sourceMatchesForRule(app, "laravel.security.upload.risky_web_types_extension_only"),
		sourceMatchesForRule(app, "laravel.security.upload.risky_web_types_mime_only"),
	)) > 0
}

func publicUploadPHPArtifacts(app model.LaravelApp) []model.ArtifactRecord {
	artifacts := []model.ArtifactRecord{}
	for _, artifact := range app.Artifacts {
		if artifact.Kind != model.ArtifactKindPublicPHPFile || !artifact.WithinPublicPath || !artifact.UploadLikePath {
			continue
		}
		artifacts = append(artifacts, artifact)
	}

	return artifacts
}

func summarizeUploadBoundarySites(matchedSites []model.NginxSite) ([]string, string) {
	configPaths := make([]string, 0, len(matchedSites))
	phpBoundaryNotes := []string{}

	for _, site := range matchedSites {
		configPaths = append(configPaths, site.ConfigPath)
		if site.UploadExecutionAllowed {
			phpBoundaryNotes = append(phpBoundaryNotes, "upload-adjacent PHP execution allowed")
			continue
		}
		if site.HasGenericPHPLocation {
			phpBoundaryNotes = append(phpBoundaryNotes, "generic PHP handling present")
		}
	}

	return configPaths, strings.Join(phpBoundaryNotes, ", ")
}

func appendUniqueTarget(affected []model.Target, seen map[string]struct{}, target model.Target) ([]model.Target, map[string]struct{}) {
	key := target.Path
	if key == "" {
		key = target.Name
	}
	if key == "" {
		key = target.Value
	}
	if key == "" {
		return affected, seen
	}
	if _, found := seen[key]; found {
		return affected, seen
	}

	seen[key] = struct{}{}
	return append(affected, target), seen
}
