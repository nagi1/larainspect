package rules

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/nagi1/larainspect/internal/model"
)

func evaluateFileExistsRule(root string, ruleID string, pattern model.RulePattern) ([]model.SourceMatch, []Issue) {
	globPattern := filepath.Join(root, filepath.FromSlash(pattern.Pattern))
	paths, err := filepath.Glob(globPattern)
	if err != nil {
		return nil, []Issue{{RuleID: ruleID, Path: globPattern, Message: "invalid file-exists glob", Err: err}}
	}

	matches := existingFileMatches(paths)
	if pattern.Negative {
		if len(matches) > 0 {
			return nil, nil
		}
		return []model.SourceMatch{{
			RuleID:       ruleID,
			RelativePath: ".",
			Detail:       fallbackNegativeDetail(pattern),
		}}, nil
	}

	return buildFileExistsMatches(root, ruleID, pattern, matches), nil
}

func existingFileMatches(paths []string) []string {
	matches := make([]string, 0, len(paths))
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil || info.IsDir() {
			continue
		}
		matches = append(matches, path)
	}
	return matches
}

func buildFileExistsMatches(root string, ruleID string, pattern model.RulePattern, paths []string) []model.SourceMatch {
	matches := make([]model.SourceMatch, 0, len(paths))
	for _, path := range paths {
		relativePath, err := filepath.Rel(root, path)
		if err != nil {
			continue
		}

		matches = append(matches, model.SourceMatch{
			RuleID:       ruleID,
			RelativePath: filepath.ToSlash(relativePath),
			Detail:       fallbackDetail(pattern, ""),
		})
	}
	return matches
}

func evaluateContentPattern(ruleID string, pattern compiledPattern, file scanFile) []model.SourceMatch {
	switch pattern.definition.Type {
	case "contains":
		return evaluateContainsPattern(ruleID, pattern, file)
	case "regex-scoped":
		return evaluateScopedPattern(ruleID, pattern, file)
	default:
		return evaluateRegexPattern(ruleID, pattern, file)
	}
}

func evaluateContainsPattern(ruleID string, pattern compiledPattern, file scanFile) []model.SourceMatch {
	matches := make([]model.SourceMatch, 0, 4)
	for index, line := range file.lines {
		if !strings.Contains(line, pattern.definition.Pattern) || matcherMatches(pattern.exclude, line) {
			continue
		}

		matches = append(matches, model.SourceMatch{
			RuleID:       ruleID,
			RelativePath: file.relativePath,
			Line:         index + 1,
			Detail:       fallbackDetail(pattern.definition, strings.TrimSpace(line)),
		})
	}
	return matches
}

func evaluateRegexPattern(ruleID string, pattern compiledPattern, file scanFile) []model.SourceMatch {
	indexes := pattern.regex.FindAllStringIndex(file.sanitized, -1)
	if len(indexes) == 0 {
		return nil
	}

	matches := make([]model.SourceMatch, 0, len(indexes))
	for _, matchIndex := range indexes {
		lineNumber := lineNumberForOffset(file.sanitized, matchIndex[0])
		lineText := lineAt(file.lines, lineNumber)
		matchText := strings.TrimSpace(file.sanitized[matchIndex[0]:matchIndex[1]])
		if matcherMatches(pattern.exclude, matchText) || matcherMatches(pattern.exclude, lineText) {
			continue
		}

		matches = append(matches, model.SourceMatch{
			RuleID:       ruleID,
			RelativePath: file.relativePath,
			Line:         lineNumber,
			Detail:       fallbackDetail(pattern.definition, strings.TrimSpace(lineText)),
		})
	}

	return matches
}

func evaluateScopedPattern(ruleID string, pattern compiledPattern, file scanFile) []model.SourceMatch {
	protected := buildProtectedRanges(file.lines, pattern.scope)
	matches := make([]model.SourceMatch, 0, 4)

	for index, line := range file.lines {
		lineNumber := index + 1
		if protected[lineNumber] || !matcherMatches(pattern.regex, line) || matcherMatches(pattern.exclude, line) {
			continue
		}

		matches = append(matches, model.SourceMatch{
			RuleID:       ruleID,
			RelativePath: file.relativePath,
			Line:         lineNumber,
			Detail:       fallbackDetail(pattern.definition, strings.TrimSpace(line)),
		})
	}

	return matches
}

func resolveTarget(root string, target string) ([]string, []Issue) {
	target = filepath.ToSlash(strings.TrimSpace(target))
	if target == "" {
		return nil, nil
	}

	paths, issues := resolveTargetGlobs(root, target)
	if needsRecursiveWalk(target) {
		walkPaths, walkIssues := resolveTargetWalk(root, target)
		paths = append(paths, walkPaths...)
		issues = append(issues, walkIssues...)
	}

	sort.Strings(paths)
	return compactPaths(paths), issues
}

func resolveTargetGlobs(root string, target string) ([]string, []Issue) {
	paths := []string{}
	issues := []Issue{}
	seen := map[string]struct{}{}

	for _, globPattern := range targetGlobs(root, target) {
		matches, err := filepath.Glob(globPattern)
		if err != nil {
			return nil, []Issue{{Path: globPattern, Message: "invalid target glob", Err: err}}
		}

		for _, match := range matches {
			appendResolvedPath(seen, match, &paths)
		}
	}

	return paths, issues
}

func resolveTargetWalk(root string, target string) ([]string, []Issue) {
	paths := []string{}
	seen := map[string]struct{}{}
	walkErr := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if entry.IsDir() {
			if skipDirectory(entry.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if targetMatchesExtension(target, path) {
			appendResolvedPath(seen, path, &paths)
		}
		return nil
	})
	if walkErr != nil {
		return nil, []Issue{{Path: root, Message: "unable to walk target files", Err: walkErr}}
	}

	return paths, nil
}

func appendResolvedPath(seen map[string]struct{}, path string, out *[]string) {
	if _, found := seen[path]; found {
		return
	}

	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return
	}

	seen[path] = struct{}{}
	*out = append(*out, path)
}

func compactPaths(paths []string) []string {
	compacted := make([]string, 0, len(paths))
	seen := map[string]struct{}{}
	for _, path := range paths {
		if _, found := seen[path]; found {
			continue
		}
		seen[path] = struct{}{}
		compacted = append(compacted, path)
	}
	return compacted
}

func targetGlobs(root string, target string) []string {
	switch target {
	case "php-files":
		return []string{filepath.Join(root, "*.php"), filepath.Join(root, "app", "*.php")}
	case "blade-files":
		return []string{filepath.Join(root, "resources", "views", "*.blade.php")}
	case "config-files":
		return []string{filepath.Join(root, "config", "*.php")}
	case "env-files":
		return []string{filepath.Join(root, ".env"), filepath.Join(root, ".env.*"), filepath.Join(root, ".env.example")}
	case "routes-files":
		return []string{filepath.Join(root, "routes", "*.php")}
	case "migration-files":
		return []string{filepath.Join(root, "database", "migrations", "*.php")}
	case "js-files":
		return []string{filepath.Join(root, "resources", "js", "*.js"), filepath.Join(root, "resources", "js", "*.ts")}
	default:
		return []string{filepath.Join(root, filepath.FromSlash(target))}
	}
}

func needsRecursiveWalk(target string) bool {
	switch target {
	case "php-files", "blade-files", "js-files":
		return true
	default:
		return false
	}
}

func targetMatchesExtension(target string, path string) bool {
	path = filepath.ToSlash(path)
	switch target {
	case "php-files":
		return strings.HasSuffix(path, ".php")
	case "blade-files":
		return strings.HasSuffix(path, ".blade.php")
	case "js-files":
		return strings.HasSuffix(path, ".js") ||
			strings.HasSuffix(path, ".ts") ||
			strings.HasSuffix(path, ".jsx") ||
			strings.HasSuffix(path, ".tsx")
	default:
		return false
	}
}

func skipDirectory(name string) bool {
	switch name {
	case "vendor", "node_modules", ".git", "storage", ".idea", ".vscode":
		return true
	default:
		return false
	}
}

func patternTargetsFile(pattern model.RulePattern, relativePath string) bool {
	for _, target := range pattern.EffectiveTargets() {
		if targetMatchesRelativePath(target, relativePath) {
			return true
		}
	}
	return false
}

func targetMatchesRelativePath(target string, relativePath string) bool {
	target = filepath.ToSlash(strings.TrimSpace(target))
	relativePath = filepath.ToSlash(filepath.Clean(relativePath))

	switch target {
	case "php-files":
		return strings.HasSuffix(relativePath, ".php")
	case "blade-files":
		return strings.HasSuffix(relativePath, ".blade.php")
	case "config-files":
		return strings.HasPrefix(relativePath, "config/") && strings.HasSuffix(relativePath, ".php")
	case "env-files":
		base := filepath.Base(relativePath)
		return base == ".env" || strings.HasPrefix(base, ".env.")
	case "routes-files":
		return strings.HasPrefix(relativePath, "routes/") && strings.HasSuffix(relativePath, ".php")
	case "migration-files":
		return strings.HasPrefix(relativePath, "database/migrations/") && strings.HasSuffix(relativePath, ".php")
	case "js-files":
		return strings.HasSuffix(relativePath, ".js") ||
			strings.HasSuffix(relativePath, ".ts") ||
			strings.HasSuffix(relativePath, ".jsx") ||
			strings.HasSuffix(relativePath, ".tsx")
	default:
		if strings.ContainsAny(target, "*?[") {
			matched, err := filepath.Match(filepath.FromSlash(target), filepath.FromSlash(relativePath))
			return err == nil && matched
		}
		return filepath.ToSlash(filepath.Clean(target)) == relativePath
	}
}

func loadScanFile(root string, absolutePath string, cache map[string]scanFile) (scanFile, bool, []Issue) {
	if file, found := cache[absolutePath]; found {
		return file, true, nil
	}

	info, err := os.Stat(absolutePath)
	if err != nil {
		return scanFile{}, false, []Issue{{Path: absolutePath, Message: "unable to stat target file", Err: err}}
	}
	if info.IsDir() || info.Size() > maxRuleFileBytes {
		return scanFile{}, false, nil
	}

	fileBytes, err := os.ReadFile(absolutePath)
	if err != nil {
		return scanFile{}, false, []Issue{{Path: absolutePath, Message: "unable to read target file", Err: err}}
	}

	relativePath, err := filepath.Rel(root, absolutePath)
	if err != nil {
		return scanFile{}, false, nil
	}

	file := newScanFile(filepath.ToSlash(relativePath), string(fileBytes))
	file.absolutePath = absolutePath
	cache[absolutePath] = file
	return file, true, nil
}

func compactMatches(matches []model.SourceMatch) []model.SourceMatch {
	compacted := make([]model.SourceMatch, 0, len(matches))
	seen := map[string]struct{}{}

	for _, match := range matches {
		key := match.RuleID + "\x00" + match.RelativePath + "\x00" + fmt.Sprintf("%d", match.Line) + "\x00" + match.Detail
		if _, found := seen[key]; found {
			continue
		}
		seen[key] = struct{}{}
		compacted = append(compacted, match)
	}

	return compacted
}

func lineNumberForOffset(fileContents string, offset int) int {
	if offset <= 0 {
		return 1
	}
	return strings.Count(fileContents[:offset], "\n") + 1
}

func lineAt(lines []string, lineNumber int) string {
	if lineNumber <= 0 || lineNumber > len(lines) {
		return ""
	}
	return lines[lineNumber-1]
}

func fallbackDetail(pattern model.RulePattern, line string) string {
	if trimmed := strings.TrimSpace(pattern.Detail); trimmed != "" {
		return trimmed
	}
	return strings.TrimSpace(line)
}

func fallbackNegativeDetail(pattern model.RulePattern) string {
	if trimmed := strings.TrimSpace(pattern.Detail); trimmed != "" {
		return trimmed
	}
	return "required pattern not present"
}

func matcherMatches(matcher compiledMatcher, value string) bool {
	return matcher != nil && matcher.MatchString(value)
}
