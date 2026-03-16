package cli

import (
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/nagi1/larainspect/internal/model"
	"github.com/nagi1/larainspect/internal/ux"
)

type presetIdentityDefaults struct {
	deployUsers   []string
	runtimeUsers  []string
	runtimeGroups []string
	webUsers      []string
	webGroups     []string
}

type setupPHPFPMPool struct {
	ConfigPath string
	Name       string
	User       string
	Group      string
}

func resolveGeneratedIdentityConfig(stdin io.Reader, stderr io.Writer, preset configPreset, inspector hostInspector, config model.AuditConfig) (model.IdentityConfig, error) {
	guessedIdentities := guessGeneratedIdentityConfig(preset, inspector, config)
	if generatedIdentityConfigComplete(guessedIdentities) {
		return guessedIdentities, nil
	}

	return promptToCompleteIdentityConfig(stdin, stderr, guessedIdentities)
}

func promptToCompleteIdentityConfig(stdin io.Reader, stderr io.Writer, defaults model.IdentityConfig) (model.IdentityConfig, error) {
	answers, err := ux.Prompter{Input: stdin, Output: stderr}.ResolveIdentityAnswers(ux.IdentityAnswers{
		DeployUsers:   cloneStrings(defaults.DeployUsers),
		RuntimeUsers:  cloneStrings(defaults.RuntimeUsers),
		RuntimeGroups: cloneStrings(defaults.RuntimeGroups),
		WebUsers:      cloneStrings(defaults.WebUsers),
		WebGroups:     cloneStrings(defaults.WebGroups),
	})
	if err != nil {
		return model.IdentityConfig{}, err
	}

	return normalizeIdentityConfig(model.IdentityConfig{
		DeployUsers:   answers.DeployUsers,
		RuntimeUsers:  answers.RuntimeUsers,
		RuntimeGroups: answers.RuntimeGroups,
		WebUsers:      answers.WebUsers,
		WebGroups:     answers.WebGroups,
	}), nil
}

func guessGeneratedIdentityConfig(preset configPreset, inspector hostInspector, config model.AuditConfig) model.IdentityConfig {
	defaults := presetDefaultIdentities(preset, config.AppPath)
	runtimeUsers, runtimeGroups := guessRuntimeIdentities(inspector, config)
	webUsers, webGroups := guessWebIdentities(preset, inspector, config)

	identities := model.IdentityConfig{
		DeployUsers:   guessDeployUsers(inspector, config, defaults, runtimeUsers, webUsers),
		RuntimeUsers:  selectIdentityValues(runtimeUsers, defaults.runtimeUsers),
		RuntimeGroups: selectIdentityValues(runtimeGroups, defaults.runtimeGroups),
		WebUsers:      selectIdentityValues(webUsers, defaults.webUsers),
		WebGroups:     selectIdentityValues(webGroups, defaults.webGroups),
	}

	if len(identities.RuntimeGroups) == 0 && len(identities.RuntimeUsers) == 1 {
		identities.RuntimeGroups = cloneStrings(identities.RuntimeUsers)
	}
	if len(identities.WebGroups) == 0 && len(identities.WebUsers) == 1 {
		identities.WebGroups = cloneStrings(identities.WebUsers)
	}

	return normalizeIdentityConfig(identities)
}

func presetDefaultIdentities(preset configPreset, appPath string) presetIdentityDefaults {
	accountUser := homeDirectoryUser(appPath)

	switch preset {
	case presetForge:
		return presetIdentityDefaults{
			deployUsers:   []string{"forge"},
			runtimeUsers:  []string{"forge"},
			runtimeGroups: []string{"forge"},
			webUsers:      []string{"www-data"},
			webGroups:     []string{"www-data"},
		}
	case presetAAPanel:
		return presetIdentityDefaults{
			deployUsers:   []string{"www"},
			runtimeUsers:  []string{"www"},
			runtimeGroups: []string{"www"},
			webUsers:      []string{"www"},
			webGroups:     []string{"www"},
		}
	case presetCPanel:
		return presetIdentityDefaults{
			deployUsers:   normalizeIdentityList([]string{accountUser}),
			runtimeUsers:  normalizeIdentityList([]string{accountUser}),
			runtimeGroups: normalizeIdentityList([]string{accountUser}),
			webUsers:      []string{"nobody"},
			webGroups:     []string{"nobody"},
		}
	default:
		return presetIdentityDefaults{}
	}
}

func guessDeployUsers(inspector hostInspector, config model.AuditConfig, defaults presetIdentityDefaults, runtimeUsers []string, webUsers []string) []string {
	deployUsers := cloneStrings(defaults.deployUsers)
	if appPathUser := homeDirectoryUser(config.AppPath); appPathUser != "" {
		deployUsers = append(deployUsers, appPathUser)
	}

	ownerName, err := appPathOwnerName(inspector, config.AppPath)
	if err != nil || ownerName == "" || strings.EqualFold(ownerName, "root") {
		return normalizeIdentityList(deployUsers)
	}
	if identitySliceContainsFold(runtimeUsers, ownerName) || identitySliceContainsFold(webUsers, ownerName) {
		return normalizeIdentityList(deployUsers)
	}

	deployUsers = append(deployUsers, ownerName)
	return normalizeIdentityList(deployUsers)
}

func appPathOwnerName(inspector hostInspector, appPath string) (string, error) {
	if inspector.lookupOwner == nil || strings.TrimSpace(appPath) == "" {
		return "", nil
	}

	return inspector.lookupOwner(appPath)
}

func guessRuntimeIdentities(inspector hostInspector, config model.AuditConfig) ([]string, []string) {
	pools := discoverSetupPHPFPMPools(inspector, config)
	if len(pools) == 0 {
		return nil, nil
	}

	selectedPools := narrowSetupPHPFPMPoolsToApp(pools, config.AppPath)
	if len(selectedPools) == 0 {
		selectedPools = pools
	}

	users := []string{}
	groups := []string{}
	for _, pool := range selectedPools {
		users = append(users, pool.User)
		groups = append(groups, pool.Group)
	}

	return collapseAmbiguousIdentityList(users), collapseAmbiguousIdentityList(groups)
}

func discoverSetupPHPFPMPools(inspector hostInspector, config model.AuditConfig) []setupPHPFPMPool {
	pools := []setupPHPFPMPool{}
	for _, pattern := range config.NormalizedPHPFPMPoolPatterns() {
		for _, configPath := range globMatches(inspector, pattern) {
			contents, err := inspector.readFile(configPath)
			if err != nil {
				continue
			}

			pools = append(pools, parseSetupPHPFPMPools(configPath, string(contents))...)
		}
	}

	return pools
}

func collapseAmbiguousIdentityList(values []string) []string {
	normalizedValues := normalizeIdentityList(values)
	if len(normalizedValues) > 1 {
		return nil
	}

	return normalizedValues
}

func guessWebIdentities(preset configPreset, inspector hostInspector, config model.AuditConfig) ([]string, []string) {
	for _, configPath := range candidateNginxMainConfigPaths() {
		if !pathExists(inspector, configPath) {
			continue
		}

		contents, err := inspector.readFile(configPath)
		if err != nil {
			continue
		}

		userName, groupName := parseNginxUserDirective(string(contents))
		if userName == "" {
			continue
		}
		if groupName == "" {
			groupName = userName
		}

		return normalizeIdentityList([]string{userName}), normalizeIdentityList([]string{groupName})
	}

	return fallbackWebIdentities(preset, config)
}

func fallbackWebIdentities(preset configPreset, config model.AuditConfig) ([]string, []string) {
	defaults := presetDefaultIdentities(preset, config.AppPath)
	if len(defaults.webUsers) > 0 || len(defaults.webGroups) > 0 {
		return defaults.webUsers, defaults.webGroups
	}

	switch config.NormalizedOSFamily() {
	case "debian":
		return []string{"www-data"}, []string{"www-data"}
	case "rhel":
		return []string{"nginx"}, []string{"nginx"}
	default:
		return nil, nil
	}
}

func generatedIdentityConfigComplete(identities model.IdentityConfig) bool {
	return len(identities.DeployUsers) > 0 &&
		len(identities.RuntimeUsers) > 0 &&
		len(identities.RuntimeGroups) > 0 &&
		len(identities.WebUsers) > 0 &&
		len(identities.WebGroups) > 0
}

func normalizeIdentityConfig(identities model.IdentityConfig) model.IdentityConfig {
	identities.DeployUsers = normalizeIdentityList(identities.DeployUsers)
	identities.RuntimeUsers = normalizeIdentityList(identities.RuntimeUsers)
	identities.RuntimeGroups = normalizeIdentityList(identities.RuntimeGroups)
	identities.WebUsers = normalizeIdentityList(identities.WebUsers)
	identities.WebGroups = normalizeIdentityList(identities.WebGroups)
	return identities
}

func normalizeIdentityList(values []string) []string {
	if len(values) == 0 {
		return nil
	}

	seenValues := map[string]struct{}{}
	normalizedValues := make([]string, 0, len(values))
	for _, value := range values {
		trimmedValue := strings.TrimSpace(value)
		if trimmedValue == "" {
			continue
		}

		lookupKey := strings.ToLower(trimmedValue)
		if _, found := seenValues[lookupKey]; found {
			continue
		}

		seenValues[lookupKey] = struct{}{}
		normalizedValues = append(normalizedValues, trimmedValue)
	}

	if len(normalizedValues) == 0 {
		return nil
	}

	sort.Slice(normalizedValues, func(left int, right int) bool {
		return strings.ToLower(normalizedValues[left]) < strings.ToLower(normalizedValues[right])
	})

	return normalizedValues
}

func selectIdentityValues(values []string, fallback []string) []string {
	normalizedValues := normalizeIdentityList(values)
	if len(normalizedValues) != 0 {
		return normalizedValues
	}

	return normalizeIdentityList(fallback)
}

func identitySliceContainsFold(values []string, candidate string) bool {
	trimmedCandidate := strings.TrimSpace(candidate)
	if trimmedCandidate == "" {
		return false
	}

	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), trimmedCandidate) {
			return true
		}
	}

	return false
}

func candidateNginxMainConfigPaths() []string {
	return []string{
		"/etc/nginx/nginx.conf",
		"/www/server/nginx/conf/nginx.conf",
		"/usr/local/nginx/conf/nginx.conf",
	}
}

func parseNginxUserDirective(contents string) (string, string) {
	for _, line := range strings.Split(contents, "\n") {
		trimmedLine := strings.TrimSpace(line)
		if trimmedLine == "" || strings.HasPrefix(trimmedLine, "#") {
			continue
		}
		if commentIndex := strings.Index(trimmedLine, "#"); commentIndex >= 0 {
			trimmedLine = strings.TrimSpace(trimmedLine[:commentIndex])
		}
		if !strings.HasPrefix(strings.ToLower(trimmedLine), "user ") {
			continue
		}

		trimmedLine = strings.TrimSuffix(strings.TrimSpace(trimmedLine), ";")
		fields := strings.Fields(trimmedLine)
		if len(fields) < 2 {
			return "", ""
		}

		userName := fields[1]
		groupName := ""
		if len(fields) > 2 {
			groupName = fields[2]
		}
		return userName, groupName
	}

	return "", ""
}

func parseSetupPHPFPMPools(configPath string, contents string) []setupPHPFPMPool {
	pools := []setupPHPFPMPool{}
	var currentPool *setupPHPFPMPool

	for _, line := range strings.Split(contents, "\n") {
		trimmedLine := strings.TrimSpace(line)
		if trimmedLine == "" || strings.HasPrefix(trimmedLine, ";") || strings.HasPrefix(trimmedLine, "#") {
			continue
		}

		if sectionName, ok := iniSectionName(trimmedLine); ok {
			if currentPool != nil {
				pools = append(pools, *currentPool)
			}
			currentPool = &setupPHPFPMPool{ConfigPath: configPath, Name: sectionName}
			continue
		}

		if currentPool == nil {
			continue
		}

		key, value, ok := strings.Cut(trimmedLine, "=")
		if !ok {
			continue
		}

		switch strings.ToLower(strings.TrimSpace(key)) {
		case "user":
			currentPool.User = strings.TrimSpace(value)
		case "group":
			currentPool.Group = strings.TrimSpace(value)
		}
	}

	if currentPool != nil {
		pools = append(pools, *currentPool)
	}

	return pools
}

func iniSectionName(line string) (string, bool) {
	if !strings.HasPrefix(line, "[") || !strings.HasSuffix(line, "]") {
		return "", false
	}

	sectionName := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "["), "]"))
	if sectionName == "" {
		return "", false
	}

	return sectionName, true
}

func narrowSetupPHPFPMPoolsToApp(pools []setupPHPFPMPool, appPath string) []setupPHPFPMPool {
	candidates := setupAppIdentifierCandidates(appPath)
	if len(candidates) == 0 {
		return nil
	}

	narrowedPools := []setupPHPFPMPool{}
	for _, pool := range pools {
		searchText := strings.ToLower(pool.Name + " " + filepath.Base(pool.ConfigPath))
		for _, candidate := range candidates {
			if strings.Contains(searchText, candidate) {
				narrowedPools = append(narrowedPools, pool)
				break
			}
		}
	}

	return narrowedPools
}

func setupAppIdentifierCandidates(appPath string) []string {
	trimmedPath := strings.TrimSpace(appPath)
	if trimmedPath == "" {
		return nil
	}

	candidateNames := []string{}
	baseName := strings.ToLower(filepath.Base(trimmedPath))
	if baseName != "" && baseName != "." && baseName != string(filepath.Separator) && baseName != "current" && baseName != "public_html" {
		candidateNames = append(candidateNames, baseName)
	}

	parentName := strings.ToLower(filepath.Base(filepath.Dir(trimmedPath)))
	if parentName != "" && parentName != "." && parentName != "current" && parentName != "public_html" {
		candidateNames = append(candidateNames, parentName)
	}

	return normalizeIdentityList(candidateNames)
}

func homeDirectoryUser(path string) string {
	trimmedPath := strings.TrimSpace(filepath.Clean(path))
	if !strings.HasPrefix(trimmedPath, "/home/") {
		return ""
	}

	parts := strings.Split(strings.TrimPrefix(trimmedPath, "/home/"), string(filepath.Separator))
	if len(parts) == 0 {
		return ""
	}

	return strings.TrimSpace(parts[0])
}

func lookupPathOwnerName(path string) (string, error) {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return "", err
	}

	stat, ok := fileInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return "", fmt.Errorf("unsupported file owner lookup for %s", path)
	}

	resolvedUser, err := user.LookupId(strconv.FormatUint(uint64(stat.Uid), 10))
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(resolvedUser.Username), nil
}
