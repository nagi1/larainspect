package rules_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/nagi1/larainspect/internal/model"
	"github.com/nagi1/larainspect/internal/rules"
)

func TestLoadAppliesOverridesAndCustomDirectories(t *testing.T) {
	t.Parallel()

	customDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(customDir, "team.yaml"), []byte(`rules:
  - id: team.custom.rule
    title: Team custom rule
    severity: low
    confidence: possible
    class: heuristic_finding
    enabled: true
    patterns:
      - type: contains
        target: .env.example
        pattern: TEAM_SECRET
`), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	definitions, issues := rules.Load(model.RuleConfig{
		Disable:    []string{"laravel.debug.dd_call"},
		CustomDirs: []string{customDir},
		Override: map[string]model.RuleOverride{
			"laravel.inject.eval": {Severity: model.SeverityLow},
		},
	})
	if len(issues) != 0 {
		t.Fatalf("Load() issues = %+v", issues)
	}

	if containsRuleID(definitions, "laravel.debug.dd_call") {
		t.Fatal("expected disabled embedded rule to be removed")
	}
	if !containsRuleID(definitions, "team.custom.rule") {
		t.Fatal("expected custom rule to be loaded")
	}

	for _, definition := range definitions {
		if definition.ID != "laravel.inject.eval" {
			continue
		}
		if definition.Severity != model.SeverityLow {
			t.Fatalf("expected override severity low, got %q", definition.Severity)
		}
		return
	}

	t.Fatal("expected laravel.inject.eval to remain loaded")
}

func TestEngineScanRootSupportsWardPatternTypes(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	mustWriteRuleTestFile(t, filepath.Join(root, "routes", "api.php"), "<?php\nRoute::get('/admin', fn () => 'ok');\n")
	mustWriteRuleTestFile(t, filepath.Join(root, "app", "Policies", "TenantPolicy.php"), "<?php\nGate::define('view', function () {\n    abort(403);\n});\n\nabort(401);\n")
	mustWriteRuleTestFile(t, filepath.Join(root, "resources", "views", "dashboard.blade.php"), "<script>\nconst state = \"{{ $state }}\";\n</script>\n")
	mustWriteRuleTestFile(t, filepath.Join(root, "storage", "debugbar", "trace.json"), "{}")

	definitions := []model.RuleDefinition{
		ruleDefinition("test.regex", model.RulePattern{
			Type:    "regex",
			Target:  "routes-files",
			Pattern: `Route::get\('/admin'`,
			Detail:  "admin route detected",
		}),
		ruleDefinition("test.contains", model.RulePattern{
			Type:    "contains",
			Target:  "routes-files",
			Pattern: "Route::get",
			Detail:  "route registration detected",
		}),
		ruleDefinition("test.file_exists", model.RulePattern{
			Type:    "file-exists",
			Pattern: "storage/debugbar/*.json",
			Detail:  "debugbar artifact present",
		}),
		ruleDefinition("test.regex_scoped", model.RulePattern{
			Type:         "regex-scoped",
			Target:       "php-files",
			Pattern:      `abort\(`,
			ScopeExclude: `Gate::define`,
			Detail:       "abort outside protected scope",
		}),
		ruleDefinition("test.negative", model.RulePattern{
			Type:     "regex",
			Target:   "routes-files",
			Pattern:  `auth:sanctum`,
			Negative: true,
			Detail:   "auth middleware missing",
		}),
	}

	engine, issues := rules.Compile(definitions)
	if len(issues) != 0 {
		t.Fatalf("Compile() issues = %+v", issues)
	}

	matches, scanIssues := engine.ScanRoot(context.Background(), root)
	if len(scanIssues) != 0 {
		t.Fatalf("ScanRoot() issues = %+v", scanIssues)
	}

	assertRuleMatch(t, matches, "test.regex")
	assertRuleMatch(t, matches, "test.contains")
	assertRuleMatch(t, matches, "test.file_exists")
	assertRuleMatch(t, matches, "test.regex_scoped")
	assertRuleMatch(t, matches, "test.negative")

	for _, match := range matches {
		if match.RuleID == "test.regex_scoped" && match.Line != 6 {
			t.Fatalf("expected scoped regex to keep only the unprotected abort() at line 6, got %+v", match)
		}
	}
}

func TestEngineMatchFileSupportsMultilineRegex(t *testing.T) {
	t.Parallel()

	engine, issues := rules.Compile([]model.RuleDefinition{
		ruleDefinition("test.multiline", model.RulePattern{
			Type:    "regex",
			Target:  "blade-files",
			Pattern: `(?is)<script[^>]*>.*\{\{\s*\$[^}]+\}\}.*</script>`,
			Detail:  "script interpolation",
		}),
	})
	if len(issues) != 0 {
		t.Fatalf("Compile() issues = %+v", issues)
	}

	matches := engine.MatchFile("resources/views/home.blade.php", "<script>\nconst state = \"{{ $state }}\";\n</script>\n")
	if len(matches) != 1 {
		t.Fatalf("expected 1 multiline match, got %+v", matches)
	}
	if matches[0].Line != 1 {
		t.Fatalf("expected multiline match to anchor on line 1, got %+v", matches[0])
	}
}

func ruleDefinition(id string, pattern model.RulePattern) model.RuleDefinition {
	enabled := true
	return model.RuleDefinition{
		ID:         id,
		Title:      id,
		Severity:   model.SeverityMedium,
		Confidence: model.ConfidencePossible,
		Class:      model.FindingClassHeuristic,
		Enabled:    &enabled,
		Patterns:   []model.RulePattern{pattern},
	}
}

func containsRuleID(definitions []model.RuleDefinition, ruleID string) bool {
	for _, definition := range definitions {
		if definition.ID == ruleID {
			return true
		}
	}
	return false
}

func assertRuleMatch(t *testing.T, matches []model.SourceMatch, ruleID string) {
	t.Helper()

	for _, match := range matches {
		if match.RuleID == ruleID {
			return
		}
	}

	t.Fatalf("expected rule %q in matches %+v", ruleID, matches)
}

func mustWriteRuleTestFile(t *testing.T, path string, contents string) {
	t.Helper()

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
}
