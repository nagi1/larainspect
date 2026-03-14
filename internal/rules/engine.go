package rules

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/nagi1/larainspect/internal/model"
)

const maxRuleFileBytes = 256 * 1024

type Issue struct {
	RuleID  string
	Path    string
	Message string
	Err     error
}

func (issue Issue) Error() string {
	switch {
	case issue.Err != nil && issue.Message != "":
		return fmt.Sprintf("%s: %v", issue.Message, issue.Err)
	case issue.Err != nil:
		return issue.Err.Error()
	default:
		return issue.Message
	}
}

type Engine struct {
	rules   []compiledRule
	ruleMap map[string]model.RuleDefinition
}

type compiledRule struct {
	definition model.RuleDefinition
	patterns   []compiledPattern
}

type compiledPattern struct {
	definition model.RulePattern
	regex      compiledMatcher
	exclude    compiledMatcher
	scope      compiledMatcher
}

type compiledMatcher interface {
	MatchString(string) bool
	FindAllStringIndex(string, int) [][]int
}

type scanFile struct {
	absolutePath string
	relativePath string
	raw          string
	sanitized    string
	lines        []string
}

func New(config model.RuleConfig) (Engine, []Issue) {
	definitions, issues := Load(config)
	engine, compileIssues := Compile(definitions)
	return engine, append(issues, compileIssues...)
}

func (engine Engine) RuleByID(id string) (model.RuleDefinition, bool) {
	definition, found := engine.ruleMap[id]
	return definition, found
}

func (engine Engine) Definitions() []model.RuleDefinition {
	definitions := make([]model.RuleDefinition, 0, len(engine.rules))
	for _, rule := range engine.rules {
		definitions = append(definitions, rule.definition)
	}
	return definitions
}

func (engine Engine) MatchFile(relativePath string, fileContents string) []model.SourceMatch {
	file := newScanFile(filepath.ToSlash(filepath.Clean(relativePath)), fileContents)
	matches := []model.SourceMatch{}

	for _, rule := range engine.rules {
		if !rule.definition.IsEnabled() {
			continue
		}

		for _, pattern := range rule.patterns {
			if skipInlinePattern(pattern.definition) || !patternTargetsFile(pattern.definition, file.relativePath) {
				continue
			}

			matches = append(matches, evaluateContentPattern(rule.definition.ID, pattern, file)...)
		}
	}

	model.SortSourceMatches(matches)
	return compactMatches(matches)
}

func (engine Engine) ScanRoot(ctx context.Context, root string) ([]model.SourceMatch, []Issue) {
	root = filepath.Clean(root)
	targetCache := map[string][]string{}
	fileCache := map[string]scanFile{}
	matches := make([]model.SourceMatch, 0, len(engine.rules)*4)
	issues := make([]Issue, 0, 4)

	for _, rule := range engine.rules {
		if !rule.definition.IsEnabled() {
			continue
		}

		for _, pattern := range rule.patterns {
			if ctx.Err() != nil {
				return matches, issues
			}

			patternMatches, patternIssues := scanPattern(ctx, root, rule.definition.ID, pattern, targetCache, fileCache)
			matches = append(matches, patternMatches...)
			issues = append(issues, patternIssues...)
		}
	}

	model.SortSourceMatches(matches)
	return compactMatches(matches), issues
}

func scanPattern(
	ctx context.Context,
	root string,
	ruleID string,
	pattern compiledPattern,
	targetCache map[string][]string,
	fileCache map[string]scanFile,
) ([]model.SourceMatch, []Issue) {
	if pattern.definition.Type == "file-exists" {
		return evaluateFileExistsRule(root, ruleID, pattern.definition)
	}

	targets := pattern.definition.EffectiveTargets()
	if len(targets) == 0 {
		return nil, nil
	}

	matches := make([]model.SourceMatch, 0, 8)
	issues := make([]Issue, 0, 2)
	for _, target := range targets {
		if ctx.Err() != nil {
			return matches, issues
		}

		files, resolveIssues := cachedTargetFiles(root, target, targetCache)
		issues = append(issues, resolveIssues...)
		if len(files) == 0 {
			continue
		}

		targetMatches, targetIssues := scanTargetFiles(ctx, root, ruleID, pattern, files, fileCache)
		matches = append(matches, targetMatches...)
		issues = append(issues, targetIssues...)
	}

	return matches, issues
}

func cachedTargetFiles(root string, target string, targetCache map[string][]string) ([]string, []Issue) {
	if files, found := targetCache[target]; found {
		return files, nil
	}

	files, issues := resolveTarget(root, target)
	targetCache[target] = files
	return files, issues
}

func scanTargetFiles(
	ctx context.Context,
	root string,
	ruleID string,
	pattern compiledPattern,
	files []string,
	fileCache map[string]scanFile,
) ([]model.SourceMatch, []Issue) {
	matches := make([]model.SourceMatch, 0, len(files))
	issues := make([]Issue, 0, 2)

	for _, absolutePath := range files {
		if ctx.Err() != nil {
			return matches, issues
		}

		file, found, fileIssues := loadScanFile(root, absolutePath, fileCache)
		issues = append(issues, fileIssues...)
		if !found {
			continue
		}

		contentMatches := evaluateContentPattern(ruleID, pattern, file)
		if !pattern.definition.Negative {
			matches = append(matches, contentMatches...)
			continue
		}
		if len(contentMatches) > 0 {
			continue
		}

		matches = append(matches, model.SourceMatch{
			RuleID:       ruleID,
			RelativePath: file.relativePath,
			Detail:       fallbackNegativeDetail(pattern.definition),
		})
	}

	return matches, issues
}

func skipInlinePattern(pattern model.RulePattern) bool {
	return pattern.Negative || pattern.Type == "file-exists"
}

func newScanFile(relativePath string, raw string) scanFile {
	file := scanFile{
		relativePath: relativePath,
		raw:          raw,
		sanitized:    sanitizeContent(relativePath, raw),
	}
	file.lines = strings.Split(file.sanitized, "\n")
	return file
}
