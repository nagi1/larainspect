package discovery

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/nagi1/larainspect/internal/model"
)

func parseCronEntries(sourcePath string, contents string) ([]model.CronEntry, error) {
	entries := []model.CronEntry{}

	for lineNumber, rawLine := range strings.Split(contents, "\n") {
		line := strings.TrimSpace(rawLine)
		if shouldSkipCronLine(line) {
			continue
		}

		entry, parseErr := parseCronEntryLine(sourcePath, lineNumber, line)
		if parseErr != nil {
			return nil, parseErr
		}

		if entry.Command == "" {
			continue
		}
		entries = append(entries, entry)
	}

	return entries, nil
}

func parseCronEntryLine(sourcePath string, lineNumber int, line string) (model.CronEntry, error) {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return model.CronEntry{}, nil
	}

	entry := model.CronEntry{SourcePath: filepath.Clean(sourcePath)}
	if strings.HasPrefix(fields[0], "@") {
		if len(fields) < 3 {
			return model.CronEntry{}, fmt.Errorf("cron macro line %d in %s is incomplete", lineNumber+1, sourcePath)
		}

		entry.Schedule = fields[0]
		entry.User = fields[1]
		entry.Command = strings.Join(fields[2:], " ")
		return entry, nil
	}

	if len(fields) < 7 {
		return model.CronEntry{}, fmt.Errorf("cron line %d in %s is incomplete", lineNumber+1, sourcePath)
	}

	entry.Schedule = strings.Join(fields[:5], " ")
	entry.User = fields[5]
	entry.Command = strings.Join(fields[6:], " ")
	return entry, nil
}

func parseCronSourceEntries(sourcePath string, contents string) ([]model.CronEntry, error) {
	cleanPath := filepath.Clean(sourcePath)
	if pathUsesCronScriptMode(cleanPath) {
		return parseCronScriptEntries(cleanPath, contents), nil
	}

	return parseCronEntries(cleanPath, contents)
}

func parseCronScriptEntries(sourcePath string, contents string) []model.CronEntry {
	entries := []model.CronEntry{}
	schedule := cronScheduleForScriptPath(sourcePath)
	user := cronUserForScriptPath(sourcePath)

	for _, rawLine := range strings.Split(contents, "\n") {
		line := strings.TrimSpace(rawLine)
		if shouldSkipCronScriptLine(line) {
			continue
		}

		entries = append(entries, model.CronEntry{
			SourcePath: sourcePath,
			Schedule:   schedule,
			User:       user,
			Command:    line,
		})
	}

	return entries
}

func shouldSkipCronLine(line string) bool {
	if line == "" || strings.HasPrefix(line, "#") {
		return true
	}

	return looksLikeCronEnvironmentAssignment(line)
}

func shouldSkipCronScriptLine(line string) bool {
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "set ") {
		return true
	}
	if looksLikeCronEnvironmentAssignment(line) {
		return true
	}
	if strings.HasPrefix(line, "if ") || line == "fi" || strings.HasSuffix(line, "then") {
		return true
	}

	return false
}

func pathUsesCronScriptMode(sourcePath string) bool {
	return strings.Contains(sourcePath, "/cron.daily/") ||
		strings.Contains(sourcePath, "/var/spool/cron/") ||
		strings.Contains(sourcePath, "/var/spool/cron/crontabs/")
}

func cronScheduleForScriptPath(sourcePath string) string {
	if strings.Contains(sourcePath, "/cron.daily/") {
		return "@daily"
	}

	return "@unknown"
}

func cronUserForScriptPath(sourcePath string) string {
	if strings.Contains(sourcePath, "/var/spool/cron/") {
		return filepath.Base(sourcePath)
	}

	return "root"
}

func looksLikeCronEnvironmentAssignment(line string) bool {
	key, _, foundSeparator := strings.Cut(line, "=")
	if !foundSeparator {
		return false
	}

	trimmedKey := strings.TrimSpace(key)
	return trimmedKey != "" && !strings.Contains(trimmedKey, " ")
}
