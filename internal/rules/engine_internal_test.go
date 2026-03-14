package rules

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/nagi1/larainspect/internal/model"
)

func TestIssueErrorFormatting(t *testing.T) {
	t.Parallel()

	if got := (Issue{Message: "plain message"}).Error(); got != "plain message" {
		t.Fatalf("Issue.Error() = %q", got)
	}

	if got := (Issue{Err: os.ErrNotExist}).Error(); got != os.ErrNotExist.Error() {
		t.Fatalf("Issue.Error() with err only = %q", got)
	}

	got := (Issue{Message: "broken", Err: os.ErrPermission}).Error()
	if !strings.Contains(got, "broken") || !strings.Contains(got, os.ErrPermission.Error()) {
		t.Fatalf("Issue.Error() combined = %q", got)
	}
}

func TestParseRuleFileDefaultsEnabled(t *testing.T) {
	t.Parallel()

	definitions, issues := parseRuleFile("rules.yaml", []byte(`rules:
  - id: TEST-001
    title: Example
    severity: medium
    patterns:
      - type: contains
        target: .env.example
        pattern: APP_KEY
`))
	if len(issues) != 0 {
		t.Fatalf("parseRuleFile() issues = %+v", issues)
	}
	if len(definitions) != 1 || definitions[0].Enabled == nil || !*definitions[0].Enabled {
		t.Fatalf("expected enabled default, got %+v", definitions)
	}
}

func TestParseRuleFileRejectsInvalidYAML(t *testing.T) {
	t.Parallel()

	_, issues := parseRuleFile("broken.yaml", []byte("rules: ["))
	if len(issues) != 1 {
		t.Fatalf("expected 1 parse issue, got %+v", issues)
	}
}

func TestNewLoadsEmbeddedRules(t *testing.T) {
	t.Parallel()

	engine, issues := New(model.RuleConfig{})
	if len(issues) != 0 {
		t.Fatalf("New() issues = %+v", issues)
	}
	if len(engine.rules) == 0 {
		t.Fatal("expected embedded rules to compile")
	}
}

func TestCompileValidatesRuleAndPatternFailures(t *testing.T) {
	t.Parallel()

	enabled := true
	_, issues := Compile([]model.RuleDefinition{
		{
			ID:         "broken.class",
			Title:      "Broken class",
			Severity:   model.SeverityMedium,
			Confidence: model.ConfidencePossible,
			Class:      model.FindingClassDirect,
			Enabled:    &enabled,
			Patterns: []model.RulePattern{{
				Type:    "regex",
				Target:  "php-files",
				Pattern: "[",
			}},
		},
		{
			ID:         "broken.pattern",
			Title:      "Broken pattern",
			Severity:   model.SeverityMedium,
			Confidence: model.ConfidencePossible,
			Class:      model.FindingClassHeuristic,
			Enabled:    &enabled,
			Patterns: []model.RulePattern{{
				Type:    "unsupported",
				Target:  "php-files",
				Pattern: "x",
			}},
		},
	})

	if len(issues) < 2 {
		t.Fatalf("expected validation issues, got %+v", issues)
	}
}

func TestValidateRuleCoversRequiredBranches(t *testing.T) {
	t.Parallel()

	if issues := validateRule(model.RuleDefinition{}); len(issues) == 0 {
		t.Fatal("expected missing id validation issue")
	}

	if issues := validateRule(model.RuleDefinition{ID: "x"}); len(issues) == 0 {
		t.Fatal("expected missing title validation issue")
	}

	if issues := validateRule(model.RuleDefinition{
		ID:       "x",
		Title:    "x",
		Severity: model.Severity("broken"),
		Patterns: []model.RulePattern{{Type: "contains", Target: ".env.example", Pattern: "APP_KEY"}},
	}); len(issues) == 0 {
		t.Fatal("expected invalid severity issue")
	}

	if issues := validateRule(model.RuleDefinition{
		ID:         "x",
		Title:      "x",
		Severity:   model.SeverityMedium,
		Confidence: model.Confidence("broken"),
		Patterns:   []model.RulePattern{{Type: "contains", Target: ".env.example", Pattern: "APP_KEY"}},
	}); len(issues) == 0 {
		t.Fatal("expected invalid confidence issue")
	}
}

func TestLoadDefinitionsHelpers(t *testing.T) {
	t.Parallel()

	if definitions, issues := loadDefinitionsFromDir(filepath.Join(t.TempDir(), "missing")); len(definitions) != 0 || len(issues) != 0 {
		t.Fatalf("expected missing dir to be ignored, got definitions=%+v issues=%+v", definitions, issues)
	}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "broken.yaml"), []byte("rules: ["), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if _, issues := loadDefinitionsFromDir(dir); len(issues) == 0 {
		t.Fatal("expected invalid yaml in custom dir to become an issue")
	}

	definitions, issues := loadDefinitionsFromFS(defaultRuleFS, "defaults")
	if len(issues) != 0 || len(definitions) == 0 {
		t.Fatalf("expected embedded definitions, got definitions=%d issues=%+v", len(definitions), issues)
	}

	if _, issues := loadDefinitionsFromFS(defaultRuleFS, "missing"); len(issues) == 0 {
		t.Fatal("expected missing embedded rules dir to return an issue")
	}
}

func TestApplyOverridesFiltersAndMutatesRules(t *testing.T) {
	t.Parallel()

	enabled := true
	falseValue := false
	definitions := []model.RuleDefinition{
		{ID: "one", Title: "one", Severity: model.SeverityHigh, Confidence: model.ConfidencePossible, Class: model.FindingClassHeuristic, Enabled: &enabled, Patterns: []model.RulePattern{{Type: "contains", Target: ".env.example", Pattern: "A"}}},
		{ID: "two", Title: "two", Severity: model.SeverityHigh, Confidence: model.ConfidencePossible, Class: model.FindingClassHeuristic, Enabled: &enabled, Patterns: []model.RulePattern{{Type: "contains", Target: ".env.example", Pattern: "B"}}},
	}

	result := applyOverrides(definitions, model.RuleConfig{
		Enable:  []string{"one", "two"},
		Disable: []string{"two"},
		Override: map[string]model.RuleOverride{
			"one": {Severity: model.SeverityLow, Confidence: model.ConfidenceProbable, Enabled: &falseValue},
		},
	})

	if len(result) != 1 {
		t.Fatalf("expected only one rule after filtering, got %+v", result)
	}
	if result[0].Severity != model.SeverityLow || result[0].Confidence != model.ConfidenceProbable {
		t.Fatalf("expected overrides applied, got %+v", result[0])
	}
	if result[0].Enabled == nil || *result[0].Enabled {
		t.Fatalf("expected enabled override false, got %+v", result[0].Enabled)
	}
}

func TestCompilePatternRejectsBrokenInputs(t *testing.T) {
	t.Parallel()

	cases := []model.RulePattern{
		{Type: "regex", Pattern: "x"},
		{Type: "regex", Target: "php-files"},
		{Type: "regex", Target: "php-files", Pattern: "x", ExcludePattern: "["},
		{Type: "regex-scoped", Target: "php-files", Pattern: "x", ScopeExclude: "["},
	}

	for _, pattern := range cases {
		if _, issues := compilePattern("rule", pattern); len(issues) == 0 {
			t.Fatalf("expected compilePattern issues for %+v", pattern)
		}
	}
}

func TestTargetHelpersAndMatching(t *testing.T) {
	t.Parallel()

	if got := targetGlobs("/srv/app", "config-files"); len(got) != 1 {
		t.Fatalf("targetGlobs(config-files) = %+v", got)
	}
	if got := targetGlobs("/srv/app", "js-files"); len(got) != 2 {
		t.Fatalf("targetGlobs(js-files) = %+v", got)
	}
	if got := targetGlobs("/srv/app", "env-files"); len(got) != 3 {
		t.Fatalf("targetGlobs(env-files) = %+v", got)
	}
	if got := targetGlobs("/srv/app", "*.php"); len(got) != 1 {
		t.Fatalf("targetGlobs(glob) = %+v", got)
	}
	if got := targetGlobs("/srv/app", "config/app.php"); len(got) != 1 {
		t.Fatalf("targetGlobs(literal) = %+v", got)
	}
	if !needsRecursiveWalk("php-files") || needsRecursiveWalk("config-files") {
		t.Fatal("unexpected recursive walk settings")
	}
	if !targetMatchesExtension("js-files", "/srv/app/resources/js/app.tsx") {
		t.Fatal("expected js-files extension match")
	}
	if !targetMatchesExtension("blade-files", "/srv/app/resources/views/home.blade.php") {
		t.Fatal("expected blade-files extension match")
	}
	if !targetMatchesRelativePath("config/*.php", "config/app.php") {
		t.Fatal("expected glob target to match relative path")
	}
	if !targetMatchesRelativePath("env-files", ".env.production") {
		t.Fatal("expected env-files alias to match dotenv file")
	}
	if !targetMatchesRelativePath("migration-files", "database/migrations/2024_01_01_create.php") {
		t.Fatal("expected migration-files alias to match migration")
	}
	if !targetMatchesRelativePath("js-files", "resources/js/app.ts") {
		t.Fatal("expected js-files alias to match ts file")
	}
	if !targetMatchesRelativePath("routes-files", "routes/web.php") {
		t.Fatal("expected routes-files alias to match route file")
	}
	if targetMatchesRelativePath("php-files", "README.md") {
		t.Fatal("did not expect php-files alias to match markdown")
	}
	if !patternTargetsFile(model.RulePattern{Targets: []string{"blade-files"}}, "resources/views/home.blade.php") {
		t.Fatal("expected target alias to match blade template")
	}
}

func TestSanitizersAndProtectedRangesHelpers(t *testing.T) {
	t.Parallel()

	blade := stripBladeCommentsPreservingNewlines("{{-- hidden --}}\n<div>{{ $name }}</div>")
	if strings.Contains(blade, "hidden") || !strings.Contains(blade, "{{ $name }}") {
		t.Fatalf("unexpected blade sanitize result %q", blade)
	}
	if got := stripBladeCommentsPreservingNewlines("{{-- unclosed\n<div>"); strings.Contains(got, "unclosed") || !strings.Contains(got, "\n") {
		t.Fatalf("unexpected unclosed blade sanitize result %q", got)
	}

	php := stripPHPCommentsPreservingNewlines("<?php\n// comment\n'value' /* block */\n")
	if strings.Contains(php, "comment") || !strings.Contains(php, "'value'") {
		t.Fatalf("unexpected php sanitize result %q", php)
	}
	php = stripPHPCommentsPreservingNewlines("<?php\n\"quoted // value\"\n'# still string'\n#[Attr]\n")
	if !strings.Contains(php, "\"quoted // value\"") || !strings.Contains(php, "'# still string'") || !strings.Contains(php, "#[Attr]") {
		t.Fatalf("expected quoted strings and attributes to survive comment stripping, got %q", php)
	}
	php = stripPHPCommentsPreservingNewlines("<?php\n$value = \"escaped \\\"// still string\\\"\"; # comment\n")
	if strings.Contains(php, "# comment") || !strings.Contains(php, `escaped \"// still string\"`) {
		t.Fatalf("expected escaped quoted string to survive comment stripping, got %q", php)
	}

	var builder strings.Builder
	writeWhitespacePreservingNewlines(&builder, "a\nb")
	if builder.String() != " \n " {
		t.Fatalf("unexpected whitespace builder result %q", builder.String())
	}

	protected := buildProtectedRanges([]string{
		"Gate::define('x', function () {",
		"    abort(403);",
		"}",
		"abort(401);",
	}, regexp.MustCompile(`Gate::define`))
	if !protected[1] || !protected[2] || protected[4] {
		t.Fatalf("unexpected protected ranges %+v", protected)
	}

	if depth := countBraces(`function () { echo "{not-a-brace}"; }`); depth != 0 {
		t.Fatalf("expected balanced braces, got %d", depth)
	}
	if depth := countBraces(`if ($x) { echo "\"";`); depth != 1 {
		t.Fatalf("expected unmatched opening brace depth, got %d", depth)
	}

	protected = buildProtectedRanges([]string{
		"Gate::define('x'",
		"{",
		"    abort(403);",
		"}",
		"abort(401);",
	}, regexp.MustCompile(`Gate::define`))
	if !protected[1] || !protected[2] || !protected[3] || protected[5] {
		t.Fatalf("unexpected multiline protected ranges %+v", protected)
	}
}

func TestEvaluateFileExistsRuleNegativeAndCompactMatches(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	matches, issues := evaluateFileExistsRule(root, "rule.negative", model.RulePattern{
		Type:     "file-exists",
		Pattern:  "storage/*.json",
		Negative: true,
		Detail:   "missing debug artifact",
	})
	if len(issues) != 0 || len(matches) != 1 || matches[0].Detail != "missing debug artifact" {
		t.Fatalf("unexpected negative file-exists result matches=%+v issues=%+v", matches, issues)
	}

	filePath := filepath.Join(root, "storage", "debug.json")
	if err := os.MkdirAll(filepath.Dir(filePath), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(filePath, []byte("{}"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	matches, issues = evaluateFileExistsRule(root, "rule.exists", model.RulePattern{
		Type:    "file-exists",
		Pattern: "storage/*.json",
		Detail:  "debug artifact present",
	})
	if len(issues) != 0 || len(matches) != 1 || matches[0].RelativePath != "storage/debug.json" {
		t.Fatalf("unexpected positive file-exists result matches=%+v issues=%+v", matches, issues)
	}

	matches, issues = evaluateFileExistsRule(root, "rule.none", model.RulePattern{
		Type:    "file-exists",
		Pattern: "storage/*.txt",
		Detail:  "no match expected",
	})
	if len(issues) != 0 || len(matches) != 0 {
		t.Fatalf("expected no positive file-exists match, got matches=%+v issues=%+v", matches, issues)
	}

	_, issues = evaluateFileExistsRule(root, "rule.invalid", model.RulePattern{
		Type:    "file-exists",
		Pattern: "[",
	})
	if len(issues) == 0 {
		t.Fatal("expected invalid file-exists glob issue")
	}

	dupes := compactMatches([]model.SourceMatch{
		{RuleID: "one", RelativePath: "a.php", Line: 2, Detail: "x"},
		{RuleID: "one", RelativePath: "a.php", Line: 2, Detail: "x"},
	})
	if len(dupes) != 1 {
		t.Fatalf("expected duplicate compaction, got %+v", dupes)
	}
}

func TestResolveTargetHandlesMissingAndLiteralTargets(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	filePath := filepath.Join(root, "config", "app.php")
	if err := os.MkdirAll(filepath.Dir(filePath), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(filePath, []byte("<?php"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	resolved, issues := resolveTarget(root, "config/app.php")
	if len(issues) != 0 || len(resolved) != 1 {
		t.Fatalf("resolveTarget() = %+v issues=%+v", resolved, issues)
	}

	if _, issues := resolveTarget(root, "["); len(issues) == 0 {
		t.Fatal("expected invalid target glob issue")
	}
}

func TestLoadScanFileAndFallbackHelpers(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	path := filepath.Join(root, "routes", "web.php")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(path, []byte("<?php\n// note\nRoute::get('/');\n"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	cache := map[string]scanFile{}
	file, found, issues := loadScanFile(root, path, cache)
	if len(issues) != 0 || !found || !strings.Contains(file.sanitized, "Route::get") {
		t.Fatalf("loadScanFile() file=%+v found=%t issues=%+v", file, found, issues)
	}

	cached, found, issues := loadScanFile(root, path, cache)
	if len(issues) != 0 || !found || cached.relativePath != "routes/web.php" {
		t.Fatalf("expected cached load, got file=%+v found=%t issues=%+v", cached, found, issues)
	}

	largePath := filepath.Join(root, "large.php")
	if err := os.WriteFile(largePath, make([]byte, maxRuleFileBytes+1), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if _, found, issues := loadScanFile(root, largePath, cache); len(issues) != 0 || found {
		t.Fatalf("expected oversized file to be skipped, found=%t issues=%+v", found, issues)
	}

	if got := lineAt([]string{"one", "two"}, 2); got != "two" {
		t.Fatalf("lineAt() = %q", got)
	}
	if got := lineAt([]string{"one"}, 4); got != "" {
		t.Fatalf("lineAt() out of range = %q", got)
	}
	if got := fallbackDetail(model.RulePattern{Detail: "custom"}, "line"); got != "custom" {
		t.Fatalf("fallbackDetail() = %q", got)
	}
	if got := fallbackDetail(model.RulePattern{}, " line "); got != "line" {
		t.Fatalf("fallbackDetail() default = %q", got)
	}
	if got := fallbackNegativeDetail(model.RulePattern{}); got != "required pattern not present" {
		t.Fatalf("fallbackNegativeDetail() = %q", got)
	}
}

func TestAppendResolvedPathSkipsDuplicatesAndDirectories(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	filePath := filepath.Join(root, "a.php")
	if err := os.WriteFile(filePath, []byte("<?php"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	out := []string{}
	seen := map[string]struct{}{}
	appendResolvedPath(seen, filePath, &out)
	appendResolvedPath(seen, filePath, &out)
	appendResolvedPath(seen, root, &out)

	if len(out) != 1 || out[0] != filePath {
		t.Fatalf("appendResolvedPath() = %+v", out)
	}
}

func TestMatchFileSupportsContainsWithExclude(t *testing.T) {
	t.Parallel()

	enabled := true
	engine, issues := Compile([]model.RuleDefinition{{
		ID:         "rule.contains",
		Title:      "Contains",
		Severity:   model.SeverityLow,
		Confidence: model.ConfidencePossible,
		Class:      model.FindingClassHeuristic,
		Enabled:    &enabled,
		Patterns: []model.RulePattern{{
			Type:           "contains",
			Target:         "php-files",
			Pattern:        "dump(",
			ExcludePattern: `logger`,
			Detail:         "dump call",
		}},
	}})
	if len(issues) != 0 {
		t.Fatalf("Compile() issues = %+v", issues)
	}

	matches := engine.MatchFile("app/Test.php", "<?php\nlogger()->dump();\ndump($x);\n")
	if len(matches) != 1 || matches[0].Line != 3 {
		t.Fatalf("MatchFile() = %+v", matches)
	}
}

func TestMatchFileSkipsNegativeAndFileExistsPatterns(t *testing.T) {
	t.Parallel()

	enabled := true
	engine, issues := Compile([]model.RuleDefinition{{
		ID:         "rule.skip",
		Title:      "Skip",
		Severity:   model.SeverityLow,
		Confidence: model.ConfidencePossible,
		Class:      model.FindingClassHeuristic,
		Enabled:    &enabled,
		Patterns: []model.RulePattern{
			{Type: "regex", Target: "php-files", Pattern: `phpinfo`, Negative: true},
			{Type: "file-exists", Pattern: "storage/*.json"},
		},
	}})
	if len(issues) != 0 {
		t.Fatalf("Compile() issues = %+v", issues)
	}

	if matches := engine.MatchFile("app/Test.php", "<?php phpinfo();"); len(matches) != 0 {
		t.Fatalf("expected MatchFile() to skip negative and file-exists patterns, got %+v", matches)
	}
	if matches := engine.MatchFile("resources/views/home.blade.php", "<?php phpinfo();"); len(matches) != 0 {
		t.Fatalf("expected target mismatch to skip matches, got %+v", matches)
	}
}

func TestScanRootStopsOnCanceledContext(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	enabled := true
	engine, issues := Compile([]model.RuleDefinition{{
		ID:         "rule.scan",
		Title:      "Scan",
		Severity:   model.SeverityLow,
		Confidence: model.ConfidencePossible,
		Class:      model.FindingClassHeuristic,
		Enabled:    &enabled,
		Patterns:   []model.RulePattern{{Type: "regex", Target: "php-files", Pattern: `phpinfo`}},
	}})
	if len(issues) != 0 {
		t.Fatalf("Compile() issues = %+v", issues)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	matches, scanIssues := engine.ScanRoot(ctx, root)
	if len(matches) != 0 || len(scanIssues) != 0 {
		t.Fatalf("expected canceled scan to stop cleanly, got matches=%+v issues=%+v", matches, scanIssues)
	}
}
