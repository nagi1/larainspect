package rules

import (
	"embed"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/nagi1/larainspect/internal/model"
	"gopkg.in/yaml.v3"
)

//go:embed defaults/*.yaml
var defaultRuleFS embed.FS

type ruleFile struct {
	Rules []model.RuleDefinition `yaml:"rules"`
}

func Load(config model.RuleConfig) ([]model.RuleDefinition, []Issue) {
	definitions, issues := loadDefinitionsFromFS(defaultRuleFS, "defaults")
	seenIDs := seenRuleIDs(definitions)

	for _, dir := range config.NormalizedCustomDirs() {
		loaded, loadIssues := loadDefinitionsFromDir(dir)
		issues = append(issues, loadIssues...)
		definitions, issues = appendUniqueDefinitions(definitions, loaded, dir, seenIDs, issues)
	}

	return applyOverrides(definitions, config), issues
}

func loadDefinitionsFromDir(dir string) ([]model.RuleDefinition, []Issue) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, []Issue{{Path: dir, Message: "unable to read rules directory", Err: err}}
	}

	return loadDefinitions(entries, func(name string) ([]byte, error) {
		return os.ReadFile(filepath.Join(dir, name))
	}, dir)
}

func loadDefinitionsFromFS(ruleFS fs.FS, root string) ([]model.RuleDefinition, []Issue) {
	entries, err := fs.ReadDir(ruleFS, root)
	if err != nil {
		return nil, []Issue{{Path: root, Message: "unable to read embedded rules", Err: err}}
	}

	return loadDefinitions(entries, func(name string) ([]byte, error) {
		return fs.ReadFile(ruleFS, filepath.Join(root, name))
	}, root)
}

func loadDefinitions(
	entries []fs.DirEntry,
	readFile func(string) ([]byte, error),
	basePath string,
) ([]model.RuleDefinition, []Issue) {
	names := yamlFileNames(entries)
	definitions := []model.RuleDefinition{}
	issues := []Issue{}

	for _, name := range names {
		path := filepath.Join(basePath, name)
		fileBytes, err := readFile(name)
		if err != nil {
			issues = append(issues, Issue{Path: path, Message: "unable to read rule file", Err: err})
			continue
		}

		loaded, parseIssues := parseRuleFile(path, fileBytes)
		definitions = append(definitions, loaded...)
		issues = append(issues, parseIssues...)
	}

	return definitions, issues
}

func yamlFileNames(entries []fs.DirEntry) []string {
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !isYAMLFile(entry.Name()) {
			continue
		}
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	return names
}

func isYAMLFile(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".yaml", ".yml":
		return true
	default:
		return false
	}
}

func parseRuleFile(path string, fileBytes []byte) ([]model.RuleDefinition, []Issue) {
	var parsed ruleFile
	if err := yaml.Unmarshal(fileBytes, &parsed); err != nil {
		return nil, []Issue{{Path: path, Message: "unable to parse rules yaml", Err: err}}
	}

	for index := range parsed.Rules {
		if parsed.Rules[index].Enabled != nil {
			continue
		}
		enabled := true
		parsed.Rules[index].Enabled = &enabled
	}

	return parsed.Rules, nil
}

func applyOverrides(definitions []model.RuleDefinition, config model.RuleConfig) []model.RuleDefinition {
	disabled := ruleIDSet(config.NormalizedDisable())
	enabled := ruleIDSet(config.NormalizedEnable())
	result := make([]model.RuleDefinition, 0, len(definitions))

	for _, definition := range definitions {
		if _, found := disabled[definition.ID]; found {
			continue
		}
		if len(enabled) > 0 {
			if _, found := enabled[definition.ID]; !found {
				continue
			}
		}

		if override, found := config.Override[definition.ID]; found {
			applyRuleOverride(&definition, override)
		}

		result = append(result, definition)
	}

	return result
}

func applyRuleOverride(definition *model.RuleDefinition, override model.RuleOverride) {
	if override.Severity.Valid() {
		definition.Severity = override.Severity
	}
	if override.Confidence.Valid() {
		definition.Confidence = override.Confidence
	}
	if override.Enabled != nil {
		definition.Enabled = override.Enabled
	}
}

func seenRuleIDs(definitions []model.RuleDefinition) map[string]struct{} {
	seen := make(map[string]struct{}, len(definitions))
	for _, definition := range definitions {
		seen[definition.ID] = struct{}{}
	}
	return seen
}

func appendUniqueDefinitions(
	current []model.RuleDefinition,
	loaded []model.RuleDefinition,
	sourcePath string,
	seenIDs map[string]struct{},
	issues []Issue,
) ([]model.RuleDefinition, []Issue) {
	for _, definition := range loaded {
		if _, duplicate := seenIDs[definition.ID]; duplicate {
			issues = append(issues, Issue{
				RuleID:  definition.ID,
				Path:    sourcePath,
				Message: "skipping duplicate rule id",
			})
			continue
		}

		seenIDs[definition.ID] = struct{}{}
		current = append(current, definition)
	}

	return current, issues
}

func ruleIDSet(ids []string) map[string]struct{} {
	values := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		values[id] = struct{}{}
	}
	return values
}
