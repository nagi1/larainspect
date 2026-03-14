package checks

import (
	"testing"

	"github.com/nagi1/larainspect/internal/model"
)

func TestRuleMetadataUsesFallbacksAndRuleOverrides(t *testing.T) {
	t.Parallel()

	severity, confidence, title, why, remediation := ruleMetadata(
		model.Snapshot{},
		"missing.rule",
		model.SeverityLow,
		model.ConfidencePossible,
		"fallback title",
		"fallback why",
		"fallback remediation",
	)
	if severity != model.SeverityLow || confidence != model.ConfidencePossible || title != "fallback title" || why != "fallback why" || remediation != "fallback remediation" {
		t.Fatalf("ruleMetadata() fallback = %v %v %q %q %q", severity, confidence, title, why, remediation)
	}

	snapshot := model.Snapshot{
		RuleDefinitions: map[string]model.RuleDefinition{
			"demo.rule": {
				ID:          "demo.rule",
				Severity:    model.SeverityHigh,
				Confidence:  model.ConfidenceProbable,
				Title:       "rule title",
				Why:         "rule why",
				Remediation: "rule remediation",
			},
		},
	}

	severity, confidence, title, why, remediation = ruleMetadata(
		snapshot,
		"demo.rule",
		model.SeverityLow,
		model.ConfidencePossible,
		"fallback title",
		"fallback why",
		"fallback remediation",
	)
	if severity != model.SeverityHigh || confidence != model.ConfidenceProbable || title != "rule title" || why != "rule why" || remediation != "rule remediation" {
		t.Fatalf("ruleMetadata() rule override = %v %v %q %q %q", severity, confidence, title, why, remediation)
	}
}

func TestAppendSourceMatchesPreservesOrder(t *testing.T) {
	t.Parallel()

	matches := appendSourceMatches(
		[]model.SourceMatch{{RuleID: "a"}, {RuleID: "b"}},
		[]model.SourceMatch{{RuleID: "c"}},
		nil,
	)
	if len(matches) != 3 {
		t.Fatalf("appendSourceMatches() len = %d", len(matches))
	}
	if matches[0].RuleID != "a" || matches[1].RuleID != "b" || matches[2].RuleID != "c" {
		t.Fatalf("appendSourceMatches() = %+v", matches)
	}
}
