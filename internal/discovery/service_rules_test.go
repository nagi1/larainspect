package discovery

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/nagi1/larainspect/internal/model"
	"github.com/nagi1/larainspect/internal/rules"
)

func TestCompileRuleEngineNormalizesIssuesIntoUnknowns(t *testing.T) {
	t.Parallel()

	customDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(customDir, "broken.yaml"), []byte("rules: ["), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	_, unknowns := compileRuleEngine(model.RuleConfig{CustomDirs: []string{customDir}})
	if len(unknowns) == 0 {
		t.Fatal("expected rule engine parse issue to become an unknown")
	}
	if unknowns[0].CheckID != appDiscoveryCheckID || unknowns[0].Error != model.ErrorKindParseFailure {
		t.Fatalf("unexpected rule engine unknown %+v", unknowns[0])
	}
}

func TestCollectConfiguredRuleMatchesReportsRuleIssues(t *testing.T) {
	t.Parallel()

	root := createLaravelTestApp(t, t.TempDir(), false)
	service := newTestSnapshotService()
	engine, issues := compileRuleEngine(model.RuleConfig{})
	if len(issues) != 0 {
		t.Fatalf("unexpected compile issues %+v", issues)
	}

	service.ruleEngine = engine
	service.ruleEngine, _ = rules.Compile([]model.RuleDefinition{{
		ID:         "TEAM-001",
		Title:      "Broken glob",
		Severity:   model.SeverityMedium,
		Confidence: model.ConfidencePossible,
		Class:      model.FindingClassHeuristic,
		Patterns:   []model.RulePattern{{Type: "regex", Target: "[", Pattern: "phpinfo"}},
	}})

	_, unknowns := service.collectConfiguredRuleMatches(context.Background(), root)
	if len(unknowns) != 1 {
		t.Fatalf("expected rule scan issue to become one unknown, got %+v", unknowns)
	}
}

func TestCompactUnknownsDropsDuplicatesAndEmptyEvidence(t *testing.T) {
	t.Parallel()

	unknowns := compactUnknowns([]model.Unknown{
		{
			ID:      "one",
			CheckID: appDiscoveryCheckID,
			Title:   "title",
			Reason:  "reason",
			Error:   model.ErrorKindParseFailure,
			Evidence: []model.Evidence{
				{Label: "path", Detail: ""},
				{Label: "rule_id", Detail: "TEAM-001"},
			},
		},
		{
			ID:      "two",
			CheckID: appDiscoveryCheckID,
			Title:   "title",
			Reason:  "reason",
			Error:   model.ErrorKindParseFailure,
		},
	})

	if len(unknowns) != 1 {
		t.Fatalf("expected compacted unknowns, got %+v", unknowns)
	}
	if len(unknowns[0].Evidence) != 1 || unknowns[0].Evidence[0].Detail != "TEAM-001" {
		t.Fatalf("expected empty evidence to be pruned, got %+v", unknowns[0].Evidence)
	}
}
