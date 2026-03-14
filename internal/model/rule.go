package model

import (
	"slices"
	"strings"
)

type RuleConfig struct {
	Enable     []string
	Disable    []string
	CustomDirs []string
	Override   map[string]RuleOverride
}

type RuleOverride struct {
	Severity   Severity
	Confidence Confidence
	Enabled    *bool
}

type RuleDefinition struct {
	ID          string        `yaml:"id"`
	Title       string        `yaml:"title"`
	Description string        `yaml:"description,omitempty"`
	Why         string        `yaml:"why,omitempty"`
	Severity    Severity      `yaml:"severity"`
	Confidence  Confidence    `yaml:"confidence,omitempty"`
	Class       FindingClass  `yaml:"class,omitempty"`
	Category    string        `yaml:"category,omitempty"`
	Tags        []string      `yaml:"tags,omitempty"`
	References  []string      `yaml:"references,omitempty"`
	Remediation string        `yaml:"remediation,omitempty"`
	Enabled     *bool         `yaml:"enabled,omitempty"`
	Patterns    []RulePattern `yaml:"patterns"`
}

type RulePattern struct {
	Type           string   `yaml:"type"`
	Target         string   `yaml:"target,omitempty"`
	Targets        []string `yaml:"targets,omitempty"`
	Pattern        string   `yaml:"pattern,omitempty"`
	Detail         string   `yaml:"detail,omitempty"`
	Negative       bool     `yaml:"negative,omitempty"`
	ExcludePattern string   `yaml:"exclude_pattern,omitempty"`
	ScopeExclude   string   `yaml:"scope_exclude,omitempty"`
}

func (config RuleConfig) NormalizedEnable() []string {
	return normalizeRuleIDs(config.Enable)
}

func (config RuleConfig) NormalizedDisable() []string {
	return normalizeRuleIDs(config.Disable)
}

func (config RuleConfig) NormalizedCustomDirs() []string {
	normalized := make([]string, 0, len(config.CustomDirs))
	seen := map[string]struct{}{}

	for _, dir := range config.CustomDirs {
		trimmed := strings.TrimSpace(dir)
		if trimmed == "" {
			continue
		}
		if _, found := seen[trimmed]; found {
			continue
		}
		seen[trimmed] = struct{}{}
		normalized = append(normalized, trimmed)
	}

	slices.Sort(normalized)

	return normalized
}

func (rule RuleDefinition) EffectiveConfidence() Confidence {
	if strings.TrimSpace(string(rule.Confidence)) == "" {
		return ConfidencePossible
	}

	return rule.Confidence
}

func (rule RuleDefinition) EffectiveClass() FindingClass {
	if strings.TrimSpace(string(rule.Class)) == "" {
		return FindingClassHeuristic
	}

	return rule.Class
}

func (rule RuleDefinition) IsEnabled() bool {
	return rule.Enabled == nil || *rule.Enabled
}

func (pattern RulePattern) EffectiveTargets() []string {
	targets := make([]string, 0, len(pattern.Targets)+1)
	seen := map[string]struct{}{}
	if trimmed := strings.TrimSpace(pattern.Target); trimmed != "" {
		seen[trimmed] = struct{}{}
		targets = append(targets, trimmed)
	}

	for _, target := range pattern.Targets {
		trimmed := strings.TrimSpace(target)
		if trimmed == "" {
			continue
		}
		if _, found := seen[trimmed]; found {
			continue
		}
		seen[trimmed] = struct{}{}
		targets = append(targets, trimmed)
	}

	return targets
}

func normalizeRuleIDs(values []string) []string {
	normalized := make([]string, 0, len(values))
	seen := map[string]struct{}{}

	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, found := seen[trimmed]; found {
			continue
		}
		seen[trimmed] = struct{}{}
		normalized = append(normalized, trimmed)
	}

	slices.Sort(normalized)

	return normalized
}
