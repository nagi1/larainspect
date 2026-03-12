package checks

import (
	"path/filepath"
	"slices"
	"strings"

	"github.com/nagi1/larainspect/internal/model"
)

type operationalCommandRecord struct {
	SourceType       string
	SourcePath       string
	Name             string
	RuntimeUser      string
	WorkingDirectory string
	Command          string
}

func operationalCommandRecords(snapshot model.Snapshot) []operationalCommandRecord {
	records := make([]operationalCommandRecord, 0, len(snapshot.SystemdUnits)+len(snapshot.SupervisorPrograms)+len(snapshot.CronEntries))

	for _, unit := range snapshot.SystemdUnits {
		runtimeUser := strings.TrimSpace(unit.User)
		if runtimeUser == "" {
			runtimeUser = "root"
		}

		records = append(records, operationalCommandRecord{
			SourceType:       "systemd",
			SourcePath:       unit.Path,
			Name:             unit.Name,
			RuntimeUser:      runtimeUser,
			WorkingDirectory: unit.WorkingDirectory,
			Command:          unit.ExecStart,
		})
	}

	for _, program := range snapshot.SupervisorPrograms {
		records = append(records, operationalCommandRecord{
			SourceType:       "supervisor",
			SourcePath:       program.ConfigPath,
			Name:             program.Name,
			RuntimeUser:      strings.TrimSpace(program.User),
			WorkingDirectory: program.Directory,
			Command:          program.Command,
		})
	}

	for _, cronEntry := range snapshot.CronEntries {
		records = append(records, operationalCommandRecord{
			SourceType:  "cron",
			SourcePath:  cronEntry.SourcePath,
			Name:        cronEntry.Schedule,
			RuntimeUser: strings.TrimSpace(cronEntry.User),
			Command:     cronEntry.Command,
		})
	}

	return records
}

func appsForOperationalCommand(apps []model.LaravelApp, record operationalCommandRecord) []model.LaravelApp {
	matchedApps := []model.LaravelApp{}
	searchTexts := []string{
		filepath.Clean(strings.TrimSpace(record.WorkingDirectory)),
		strings.TrimSpace(record.Command),
	}

	for _, app := range apps {
		for _, appRoot := range appCanonicalRoots(app) {
			if appRoot == "." || appRoot == "" {
				continue
			}

			if textMentionsPath(searchTexts, appRoot) || textMentionsPath(searchTexts, filepath.Join(appRoot, "artisan")) {
				matchedApps = append(matchedApps, app)
				break
			}
		}
	}

	if len(matchedApps) == 0 && len(apps) == 1 {
		if commandLooksLikeComposer(record.Command) ||
			commandLooksLikeRestoreWorkflow(record.Command) ||
			commandLooksLikeArtisanMaintenance(record.Command) ||
			commandLooksLikeScheduler(record.Command) ||
			commandLooksLikeQueueWorker(record.Command) ||
			commandLooksLikeHorizon(record.Command) {
			return []model.LaravelApp{apps[0]}
		}
	}

	return matchedApps
}

func textMentionsPath(texts []string, path string) bool {
	cleanPath := filepath.Clean(strings.TrimSpace(path))
	if cleanPath == "." || cleanPath == "" {
		return false
	}

	for _, text := range texts {
		normalizedText := filepath.Clean(strings.TrimSpace(text))
		if normalizedText == cleanPath || strings.Contains(text, cleanPath) {
			return true
		}
	}

	return false
}

func isBroadListenerAddress(address string) bool {
	normalizedAddress := strings.Trim(strings.ToLower(strings.TrimSpace(address)), "[]")
	switch normalizedAddress {
	case "", "*", "0.0.0.0", "::", "::ffff:0.0.0.0":
		return true
	default:
		return false
	}
}

func isLoopbackListenerAddress(address string) bool {
	normalizedAddress := strings.Trim(strings.ToLower(strings.TrimSpace(address)), "[]")
	switch {
	case normalizedAddress == "127.0.0.1":
		return true
	case normalizedAddress == "::1":
		return true
	case normalizedAddress == "localhost":
		return true
	default:
		return false
	}
}

func commandLooksLikeQueueWorker(command string) bool {
	normalizedCommand := strings.ToLower(strings.TrimSpace(command))
	return strings.Contains(normalizedCommand, "artisan queue:work") ||
		strings.Contains(normalizedCommand, "artisan queue:listen")
}

func commandLooksLikeHorizon(command string) bool {
	return strings.Contains(strings.ToLower(strings.TrimSpace(command)), "artisan horizon")
}

func commandLooksLikeScheduler(command string) bool {
	normalizedCommand := strings.ToLower(strings.TrimSpace(command))
	return strings.Contains(normalizedCommand, "artisan schedule:run") ||
		strings.Contains(normalizedCommand, "artisan schedule:work")
}

func commandLooksLikeComposer(command string) bool {
	normalizedCommand := strings.ToLower(strings.TrimSpace(command))
	return strings.Contains(normalizedCommand, " composer ") ||
		strings.HasPrefix(normalizedCommand, "composer ") ||
		strings.Contains(normalizedCommand, "/composer ")
}

func commandLooksLikeComposerInstallWithoutNoDev(command string) bool {
	normalizedCommand := strings.ToLower(strings.TrimSpace(command))
	if !strings.Contains(normalizedCommand, "composer install") {
		return false
	}

	return !strings.Contains(normalizedCommand, "--no-dev")
}

func commandLooksLikeDangerousPermissionReset(command string) bool {
	normalizedCommand := strings.ToLower(strings.TrimSpace(command))
	return strings.Contains(normalizedCommand, "chmod -r 777") ||
		strings.Contains(normalizedCommand, "chmod -r 775") ||
		strings.Contains(normalizedCommand, "chown -r www-data") ||
		strings.Contains(normalizedCommand, "chown -r nginx")
}

func commandLooksLikeDirectArtisanTask(command string) bool {
	normalizedCommand := strings.ToLower(strings.TrimSpace(command))
	if !strings.Contains(normalizedCommand, "artisan ") {
		return false
	}
	if commandLooksLikeScheduler(normalizedCommand) {
		return false
	}

	return true
}

func commandLooksLikeBackupOrDump(command string) bool {
	normalizedCommand := strings.ToLower(strings.TrimSpace(command))
	return strings.Contains(normalizedCommand, "mysqldump") ||
		strings.Contains(normalizedCommand, "pg_dump") ||
		strings.Contains(normalizedCommand, "tar ") ||
		strings.Contains(normalizedCommand, "zip ") ||
		strings.Contains(normalizedCommand, "backup")
}

func commandLooksLikeRestoreWorkflow(command string) bool {
	normalizedCommand := strings.ToLower(strings.TrimSpace(command))
	return strings.Contains(normalizedCommand, "restore") ||
		strings.Contains(normalizedCommand, "gunzip") ||
		strings.Contains(normalizedCommand, "unzip ") ||
		strings.Contains(normalizedCommand, "mysql <") ||
		strings.Contains(normalizedCommand, "psql <")
}

func commandLooksLikeArtisanMaintenance(command string) bool {
	normalizedCommand := strings.ToLower(strings.TrimSpace(command))
	return strings.Contains(normalizedCommand, "artisan cache:") ||
		strings.Contains(normalizedCommand, "artisan config:") ||
		strings.Contains(normalizedCommand, "artisan route:") ||
		strings.Contains(normalizedCommand, "artisan view:") ||
		strings.Contains(normalizedCommand, "artisan optimize")
}

func commandRedirectsToPublicPath(record operationalCommandRecord, app model.LaravelApp) bool {
	return commandRedirectsToPathPrefix(record.Command, filepath.Join(app.RootPath, "public")) ||
		commandRedirectsToPathPrefix(record.Command, filepath.Join(app.ResolvedPath, "public"))
}

func commandRedirectsToPathPrefix(command string, pathPrefix string) bool {
	cleanPathPrefix := filepath.Clean(strings.TrimSpace(pathPrefix))
	if cleanPathPrefix == "." || cleanPathPrefix == "" {
		return false
	}

	normalizedCommand := strings.ReplaceAll(command, ">>", ">")
	segments := strings.Split(normalizedCommand, ">")
	if len(segments) < 2 {
		return false
	}

	for _, segment := range segments[1:] {
		redirectTarget := strings.Fields(strings.TrimSpace(segment))
		if len(redirectTarget) == 0 {
			continue
		}

		if strings.HasPrefix(filepath.Clean(redirectTarget[0]), cleanPathPrefix) {
			return true
		}
	}

	return false
}

func commandMentionsPublicArchivePath(record operationalCommandRecord, app model.LaravelApp) bool {
	normalizedCommand := strings.ToLower(record.Command)
	publicPath := strings.ToLower(filepath.Join(app.RootPath, "public"))
	resolvedPublicPath := strings.ToLower(filepath.Join(app.ResolvedPath, "public"))
	return strings.Contains(normalizedCommand, publicPath) || (app.ResolvedPath != "" && strings.Contains(normalizedCommand, resolvedPublicPath))
}

func systemdUnitLooksAppAdjacent(unit model.SystemdUnit) bool {
	normalizedName := strings.ToLower(unit.Name)
	normalizedCommand := strings.ToLower(unit.ExecStart)
	return strings.Contains(normalizedName, "php") ||
		strings.Contains(normalizedName, "laravel") ||
		strings.Contains(normalizedCommand, "php-fpm") ||
		strings.Contains(normalizedCommand, "artisan ")
}

func firewallAppearsDisabled(summaries []model.FirewallSummary) bool {
	if len(summaries) == 0 {
		return false
	}

	for _, summary := range summaries {
		if summary.Enabled {
			return false
		}
	}

	return true
}

func sudoRuleTargetsOperationalPrincipal(rule model.SudoRule) bool {
	normalizedPrincipal := strings.ToLower(strings.TrimSpace(rule.Principal))
	switch normalizedPrincipal {
	case "deploy", "www-data", "nginx":
		return true
	default:
		return strings.HasPrefix(normalizedPrincipal, "%deploy") ||
			strings.HasPrefix(normalizedPrincipal, "%www-data") ||
			strings.HasPrefix(normalizedPrincipal, "%nginx")
	}
}

func pathRecordContainsUnsafeWriteBit(pathRecord model.PathRecord) bool {
	return pathRecord.Inspected && pathRecord.Exists && pathRecord.Permissions&0o022 != 0
}

func commandEvidence(record operationalCommandRecord) []model.Evidence {
	evidence := []model.Evidence{
		{Label: "source_type", Detail: record.SourceType},
		{Label: "source_path", Detail: record.SourcePath},
		{Label: "command", Detail: record.Command},
	}

	if record.Name != "" {
		evidence = append(evidence, model.Evidence{Label: "name", Detail: record.Name})
	}
	if record.RuntimeUser != "" {
		evidence = append(evidence, model.Evidence{Label: "user", Detail: record.RuntimeUser})
	}
	if record.WorkingDirectory != "" {
		evidence = append(evidence, model.Evidence{Label: "working_directory", Detail: record.WorkingDirectory})
	}

	return evidence
}

func listenerHasAnyProcessName(listener model.ListenerRecord, processNames ...string) bool {
	for _, processName := range listener.ProcessNames {
		for _, expectedName := range processNames {
			if strings.EqualFold(processName, expectedName) {
				return true
			}
		}
	}

	return false
}

func compactAppTargets(apps []model.LaravelApp) []model.Target {
	targets := make([]model.Target, 0, len(apps))
	seenPaths := map[string]struct{}{}
	for _, app := range apps {
		if _, seen := seenPaths[app.RootPath]; seen {
			continue
		}

		seenPaths[app.RootPath] = struct{}{}
		targets = append(targets, appTarget(app))
	}

	slices.SortFunc(targets, func(leftTarget model.Target, rightTarget model.Target) int {
		return strings.Compare(leftTarget.Path, rightTarget.Path)
	})

	return targets
}
