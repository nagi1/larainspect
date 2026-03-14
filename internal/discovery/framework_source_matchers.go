package discovery

import (
	"regexp"
	"strings"

	"github.com/nagi1/larainspect/internal/model"
)

func appendSourceMatchIfContainsAny(
	matches []model.SourceMatch,
	relativePath string,
	fileContents string,
	ruleID string,
	detail string,
	candidates []string,
) []model.SourceMatch {
	for _, candidate := range candidates {
		if !strings.Contains(fileContents, candidate) {
			continue
		}

		return append(matches, model.SourceMatch{
			RuleID:       ruleID,
			RelativePath: relativePath,
			Line:         lineNumberForSubstring(fileContents, candidate),
			Detail:       detail,
		})
	}

	return matches
}

func appendSourceMatchIfContainsAll(
	matches []model.SourceMatch,
	relativePath string,
	fileContents string,
	ruleID string,
	detail string,
	requiredSubstrings []string,
	anchorSubstrings []string,
) []model.SourceMatch {
	for _, requiredSubstring := range requiredSubstrings {
		if !strings.Contains(fileContents, requiredSubstring) {
			return matches
		}
	}

	for _, anchorSubstring := range anchorSubstrings {
		if !strings.Contains(fileContents, anchorSubstring) {
			continue
		}

		return append(matches, model.SourceMatch{
			RuleID:       ruleID,
			RelativePath: relativePath,
			Line:         lineNumberForSubstring(fileContents, anchorSubstring),
			Detail:       detail,
		})
	}

	if len(anchorSubstrings) == 0 {
		return append(matches, model.SourceMatch{
			RuleID:       ruleID,
			RelativePath: relativePath,
			Line:         1,
			Detail:       detail,
		})
	}

	return matches
}

func appendSourceMatchIfMatchesRegex(
	matches []model.SourceMatch,
	relativePath string,
	fileContents string,
	ruleID string,
	detail string,
	pattern *regexp.Regexp,
) []model.SourceMatch {
	matchIndexes := pattern.FindStringIndex(fileContents)
	if matchIndexes == nil {
		return matches
	}

	return append(matches, model.SourceMatch{
		RuleID:       ruleID,
		RelativePath: relativePath,
		Line:         lineNumberForOffset(fileContents, matchIndexes[0]),
		Detail:       detail,
	})
}

func appendSourceMatchIfMatchesAnyRegex(
	matches []model.SourceMatch,
	relativePath string,
	fileContents string,
	ruleID string,
	detail string,
	patterns []*regexp.Regexp,
) []model.SourceMatch {
	for _, pattern := range patterns {
		matches = appendSourceMatchIfMatchesRegex(matches, relativePath, fileContents, ruleID, detail, pattern)
		if containsRuleIDAtRelativePath(matches, ruleID, relativePath) {
			return matches
		}
	}

	return matches
}

func appendSourceMatchIfLineMatchesRegex(
	matches []model.SourceMatch,
	relativePath string,
	fileContents string,
	ruleID string,
	detail string,
	pattern *regexp.Regexp,
) []model.SourceMatch {
	lineNumber, found := firstMatchingLineNumber(fileContents, pattern, nil)
	if !found {
		return matches
	}

	return append(matches, model.SourceMatch{
		RuleID:       ruleID,
		RelativePath: relativePath,
		Line:         lineNumber,
		Detail:       detail,
	})
}

func appendSourceMatchIfLineMatchesRegexWithoutSubstrings(
	matches []model.SourceMatch,
	relativePath string,
	fileContents string,
	ruleID string,
	detail string,
	pattern *regexp.Regexp,
	forbiddenSubstrings []string,
) []model.SourceMatch {
	lineNumber, found := firstMatchingLineNumber(fileContents, pattern, forbiddenSubstrings)
	if !found {
		return matches
	}

	return append(matches, model.SourceMatch{
		RuleID:       ruleID,
		RelativePath: relativePath,
		Line:         lineNumber,
		Detail:       detail,
	})
}

func containsRuleIDAtRelativePath(matches []model.SourceMatch, ruleID string, relativePath string) bool {
	for _, match := range matches {
		if match.RuleID == ruleID && match.RelativePath == relativePath {
			return true
		}
	}

	return false
}

func lineNumberForSubstring(fileContents string, substring string) int {
	offset := strings.Index(fileContents, substring)
	if offset < 0 {
		return 0
	}

	return lineNumberForOffset(fileContents, offset)
}

func lineNumberForOffset(fileContents string, offset int) int {
	if offset <= 0 {
		return 1
	}

	return strings.Count(fileContents[:offset], "\n") + 1
}

func firstMatchingLineNumber(fileContents string, pattern *regexp.Regexp, forbiddenSubstrings []string) (int, bool) {
	for index, line := range strings.Split(fileContents, "\n") {
		if !pattern.MatchString(line) {
			continue
		}

		if lineContainsAny(line, forbiddenSubstrings) {
			continue
		}

		return index + 1, true
	}

	return 0, false
}

func lineContainsAny(line string, candidates []string) bool {
	for _, candidate := range candidates {
		if strings.Contains(line, candidate) {
			return true
		}
	}

	return false
}
