package rules

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nagi1/larainspect/internal/model"
)

func TestLoadReturnsEmbeddedDefaults(t *testing.T) {
	t.Parallel()

	definitions, issues := Load(model.RuleConfig{})
	if len(definitions) == 0 {
		t.Fatal("expected at least one embedded default rule")
	}
	for _, issue := range issues {
		t.Errorf("unexpected issue: %s", issue.Error())
	}

	seen := map[string]struct{}{}
	for _, definition := range definitions {
		if definition.ID == "" {
			t.Fatal("rule ID must not be empty")
		}
		if _, found := seen[definition.ID]; found {
			t.Fatalf("duplicate rule ID %q", definition.ID)
		}
		seen[definition.ID] = struct{}{}
	}
}

func TestLoadAppliesDisableFilter(t *testing.T) {
	t.Parallel()

	all, _ := Load(model.RuleConfig{})
	if len(all) < 2 {
		t.Skip("need at least 2 rules to test disable")
	}

	targetID := all[0].ID
	filtered, _ := Load(model.RuleConfig{Disable: []string{targetID}})

	for _, definition := range filtered {
		if definition.ID == targetID {
			t.Fatalf("disabled rule %q should not appear", targetID)
		}
	}
	if len(filtered) >= len(all) {
		t.Fatalf("expected fewer rules after disabling one: got %d, was %d", len(filtered), len(all))
	}
}

func TestLoadAppliesEnableFilter(t *testing.T) {
	t.Parallel()

	all, _ := Load(model.RuleConfig{})
	if len(all) < 2 {
		t.Skip("need at least 2 rules to test enable")
	}

	targetID := all[0].ID
	filtered, _ := Load(model.RuleConfig{Enable: []string{targetID}})

	if len(filtered) != 1 || filtered[0].ID != targetID {
		t.Fatalf("expected only %q, got %d rules", targetID, len(filtered))
	}
}

func TestLoadAppliesOverrides(t *testing.T) {
	t.Parallel()

	all, _ := Load(model.RuleConfig{})
	if len(all) == 0 {
		t.Skip("no rules to override")
	}

	targetID := all[0].ID
	originalSeverity := all[0].Severity
	newSeverity := model.SeverityLow
	if originalSeverity == model.SeverityLow {
		newSeverity = model.SeverityHigh
	}

	overridden, _ := Load(model.RuleConfig{
		Override: map[string]model.RuleOverride{
			targetID: {Severity: newSeverity},
		},
	})

	for _, definition := range overridden {
		if definition.ID == targetID {
			if definition.Severity != newSeverity {
				t.Fatalf("expected severity %q, got %q", newSeverity, definition.Severity)
			}
			return
		}
	}
	t.Fatalf("target rule %q not found in results", targetID)
}

func TestLoadCustomDirMergesRules(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeTestRuleFile(t, dir, "custom.yaml", `
rules:
  - id: custom.test.rule
    title: Custom Test Rule
    severity: medium
    patterns:
      - type: content
        pattern: CUSTOM_MATCH
`)

	definitions, issues := Load(model.RuleConfig{CustomDirs: []string{dir}})
	for _, issue := range issues {
		t.Errorf("unexpected issue: %s", issue.Error())
	}

	found := false
	for _, definition := range definitions {
		if definition.ID == "custom.test.rule" {
			found = true
			if definition.Severity != model.SeverityMedium {
				t.Fatalf("expected medium severity, got %q", definition.Severity)
			}
		}
	}
	if !found {
		t.Fatal("custom rule not found in merged definitions")
	}
}

func TestLoadCustomDirSkipsDuplicateIDs(t *testing.T) {
	t.Parallel()

	all, _ := Load(model.RuleConfig{})
	if len(all) == 0 {
		t.Skip("no rules to test duplicates against")
	}

	dir := t.TempDir()
	writeTestRuleFile(t, dir, "duplicate.yaml", `
rules:
  - id: `+all[0].ID+`
    title: Duplicate of embedded rule
    severity: low
    patterns:
      - type: content
        pattern: DUPLICATE
`)

	definitions, issues := Load(model.RuleConfig{CustomDirs: []string{dir}})

	hasDuplicateIssue := false
	for _, issue := range issues {
		if issue.RuleID == all[0].ID && issue.Message == "skipping duplicate rule id" {
			hasDuplicateIssue = true
		}
	}
	if !hasDuplicateIssue {
		t.Fatal("expected duplicate rule ID issue")
	}

	// Verify the original rule is kept, not the custom one.
	for _, definition := range definitions {
		if definition.ID == all[0].ID {
			if definition.Title == "Duplicate of embedded rule" {
				t.Fatal("custom duplicate should not override embedded rule")
			}
			return
		}
	}
}

func TestLoadCustomDirNonexistentIsIgnored(t *testing.T) {
	t.Parallel()

	definitions, issues := Load(model.RuleConfig{
		CustomDirs: []string{"/nonexistent/rules/dir"},
	})

	for _, issue := range issues {
		t.Errorf("unexpected issue for missing dir: %s", issue.Error())
	}
	if len(definitions) == 0 {
		t.Fatal("expected embedded rules even when custom dir is missing")
	}
}

func TestLoadCustomDirMalformedYAML(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeTestRuleFile(t, dir, "bad.yaml", "not: [valid: yaml: {")

	_, issues := Load(model.RuleConfig{CustomDirs: []string{dir}})

	hasParseIssue := false
	for _, issue := range issues {
		if issue.Path != "" && issue.Message == "unable to parse rules yaml" {
			hasParseIssue = true
		}
	}
	if !hasParseIssue {
		t.Fatal("expected parse issue for malformed YAML")
	}
}

func TestLoadSetsEnabledDefaultToTrue(t *testing.T) {
	t.Parallel()

	definitions, _ := Load(model.RuleConfig{})

	for _, definition := range definitions {
		if definition.Enabled == nil {
			t.Fatalf("rule %q should have Enabled set (default true)", definition.ID)
		}
		if !*definition.Enabled {
			t.Fatalf("rule %q default Enabled should be true", definition.ID)
		}
	}
}

func TestIsYAMLFileMatchesExpectedExtensions(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		want bool
	}{
		{"rules.yaml", true},
		{"rules.yml", true},
		{"rules.YAML", true},
		{"rules.json", false},
		{"rules.txt", false},
		{"rules", false},
	}

	for _, tc := range cases {
		if got := isYAMLFile(tc.name); got != tc.want {
			t.Errorf("isYAMLFile(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestParseRuleFileSetsEnabledDefault(t *testing.T) {
	t.Parallel()

	definitions, issues := parseRuleFile("test.yaml", []byte(`
rules:
  - id: test.rule
    title: Test
    severity: low
    patterns:
      - type: content
        pattern: X
`))

	if len(issues) > 0 {
		t.Fatalf("unexpected issues: %v", issues)
	}
	if len(definitions) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(definitions))
	}
	if definitions[0].Enabled == nil || !*definitions[0].Enabled {
		t.Fatal("expected Enabled to default to true")
	}
}

func TestParseRuleFileRespectsExplicitEnabled(t *testing.T) {
	t.Parallel()

	definitions, _ := parseRuleFile("test.yaml", []byte(`
rules:
  - id: test.disabled
    title: Disabled rule
    severity: low
    enabled: false
    patterns:
      - type: content
        pattern: X
`))

	if len(definitions) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(definitions))
	}
	if definitions[0].Enabled == nil || *definitions[0].Enabled {
		t.Fatal("expected Enabled to remain false")
	}
}

func TestApplyOverridesConfidenceOverride(t *testing.T) {
	t.Parallel()

	enabled := true
	definitions := []model.RuleDefinition{
		{ID: "test.rule", Severity: model.SeverityHigh, Confidence: model.ConfidenceConfirmed, Enabled: &enabled},
	}

	result := applyOverrides(definitions, model.RuleConfig{
		Override: map[string]model.RuleOverride{
			"test.rule": {Confidence: model.ConfidencePossible},
		},
	})

	if len(result) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(result))
	}
	if result[0].Confidence != model.ConfidencePossible {
		t.Fatalf("expected confidence %q, got %q", model.ConfidencePossible, result[0].Confidence)
	}
	if result[0].Severity != model.SeverityHigh {
		t.Fatalf("severity should not change, got %q", result[0].Severity)
	}
}

func TestApplyOverridesEnabledOverride(t *testing.T) {
	t.Parallel()

	enabled := true
	definitions := []model.RuleDefinition{
		{ID: "test.rule", Severity: model.SeverityHigh, Enabled: &enabled},
	}

	disabled := false
	result := applyOverrides(definitions, model.RuleConfig{
		Override: map[string]model.RuleOverride{
			"test.rule": {Enabled: &disabled},
		},
	})

	if len(result) != 1 || result[0].Enabled == nil || *result[0].Enabled {
		t.Fatal("expected Enabled to be overridden to false")
	}
}

func TestYamlFileNamesFiltersSorted(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	for _, name := range []string{"b.yaml", "a.yml", "c.txt", "d.yaml"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(""), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	entries, _ := os.ReadDir(dir)
	names := yamlFileNames(entries)

	if len(names) != 3 {
		t.Fatalf("expected 3 yaml files, got %d: %v", len(names), names)
	}
	if names[0] != "a.yml" || names[1] != "b.yaml" || names[2] != "d.yaml" {
		t.Fatalf("expected sorted yaml names, got %v", names)
	}
}

func writeTestRuleFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", name, err)
	}
}
