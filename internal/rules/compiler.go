package rules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/nagi1/larainspect/internal/model"
)

func Compile(definitions []model.RuleDefinition) (Engine, []Issue) {
	engine := Engine{
		rules:   make([]compiledRule, 0, len(definitions)),
		ruleMap: make(map[string]model.RuleDefinition, len(definitions)),
	}
	issues := []Issue{}

	for _, definition := range definitions {
		compiled, compileIssues := compileRule(definition)
		issues = append(issues, compileIssues...)
		if len(compiled.patterns) == 0 {
			continue
		}
		engine.rules = append(engine.rules, compiled)
		engine.ruleMap[definition.ID] = definition
	}

	return engine, issues
}

func compileRule(definition model.RuleDefinition) (compiledRule, []Issue) {
	issues := validateRule(definition)
	if len(issues) > 0 {
		return compiledRule{}, issues
	}

	compiled := compiledRule{
		definition: definition,
		patterns:   make([]compiledPattern, 0, len(definition.Patterns)),
	}

	for _, pattern := range definition.Patterns {
		compiledPattern, compileIssues := compilePattern(definition.ID, pattern)
		issues = append(issues, compileIssues...)
		if len(compileIssues) > 0 {
			continue
		}
		compiled.patterns = append(compiled.patterns, compiledPattern)
	}

	return compiled, issues
}

func validateRule(definition model.RuleDefinition) []Issue {
	issues := []Issue{}

	switch {
	case strings.TrimSpace(definition.ID) == "":
		issues = append(issues, Issue{Message: "rule id is required"})
	case strings.TrimSpace(definition.Title) == "":
		issues = append(issues, Issue{RuleID: definition.ID, Message: "rule title is required"})
	case !definition.Severity.Valid():
		issues = append(issues, Issue{RuleID: definition.ID, Message: fmt.Sprintf("rule severity %q is invalid", definition.Severity)})
	case definition.EffectiveClass() != model.FindingClassHeuristic:
		issues = append(issues, Issue{RuleID: definition.ID, Message: "yaml rules must use heuristic_finding class"})
	case len(definition.Patterns) == 0:
		issues = append(issues, Issue{RuleID: definition.ID, Message: "rule must declare at least one pattern"})
	}

	if confidence := definition.EffectiveConfidence(); !confidence.Valid() {
		issues = append(issues, Issue{RuleID: definition.ID, Message: fmt.Sprintf("rule confidence %q is invalid", definition.Confidence)})
	}

	return issues
}

func compilePattern(ruleID string, pattern model.RulePattern) (compiledPattern, []Issue) {
	issues := validatePattern(ruleID, pattern)
	if len(issues) > 0 {
		return compiledPattern{}, issues
	}

	compiled := compiledPattern{definition: pattern}
	regex, regexIssue := compileRegexMatcher(ruleID, "invalid regex pattern", pattern.Type == "regex" || pattern.Type == "regex-scoped", pattern.Pattern)
	if regexIssue != nil {
		return compiledPattern{}, []Issue{*regexIssue}
	}
	compiled.regex = regex

	exclude, excludeIssue := compileRegexMatcher(ruleID, "invalid exclude regex", strings.TrimSpace(pattern.ExcludePattern) != "", pattern.ExcludePattern)
	if excludeIssue != nil {
		return compiledPattern{}, []Issue{*excludeIssue}
	}
	compiled.exclude = exclude

	scope, scopeIssue := compileRegexMatcher(ruleID, "invalid scope_exclude regex", pattern.Type == "regex-scoped" && strings.TrimSpace(pattern.ScopeExclude) != "", pattern.ScopeExclude)
	if scopeIssue != nil {
		return compiledPattern{}, []Issue{*scopeIssue}
	}
	compiled.scope = scope

	return compiled, nil
}

func validatePattern(ruleID string, pattern model.RulePattern) []Issue {
	patternType := strings.TrimSpace(pattern.Type)
	targets := pattern.EffectiveTargets()
	issues := []Issue{}

	if patternType == "" {
		issues = append(issues, Issue{RuleID: ruleID, Message: "pattern type is required"})
	}
	if patternType != "file-exists" && len(targets) == 0 {
		issues = append(issues, Issue{RuleID: ruleID, Message: "content patterns require a target or targets"})
	}
	if patternType != "file-exists" && strings.TrimSpace(pattern.Pattern) == "" {
		issues = append(issues, Issue{RuleID: ruleID, Message: "content patterns require a pattern"})
	}

	switch patternType {
	case "", "regex", "contains", "file-exists", "regex-scoped":
	default:
		issues = append(issues, Issue{RuleID: ruleID, Message: fmt.Sprintf("unsupported pattern type %q", patternType)})
	}

	return issues
}

func compileRegexMatcher(ruleID string, message string, enabled bool, pattern string) (compiledMatcher, *Issue) {
	if !enabled {
		return nil, nil
	}

	compiled, err := regexp.Compile(pattern)
	if err != nil {
		return nil, &Issue{RuleID: ruleID, Message: message, Err: err}
	}

	return compiled, nil
}
