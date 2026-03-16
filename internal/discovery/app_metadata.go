package discovery

import (
	"context"
	"errors"
	"io/fs"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/nagi1/larainspect/internal/model"
	"gopkg.in/yaml.v3"
)

var deployerPHPSetRegex = regexp.MustCompile(`(?s)(?:->\s*)?set\(\s*['"]([a-z_]+)['"]\s*,\s*['"]([^'"]+)['"]\s*\)`)
var deployerPHPRequireRegex = regexp.MustCompile(`(?m)^\s*require(?:_once)?\s+__DIR__\s*\.\s*['"](/[^'"]+)['"]\s*;`)

type deploymentLayoutHint struct {
	UsesReleaseLayout bool
	CurrentPath       string
	ReleaseRoot       string
	SharedPath        string
	ActiveReleasePath string
}

type deploymentRecipeConfig struct {
	DeployPath   string
	CurrentPath  string
	ReleaseRoot  string
	SharedPath   string
	ReleasePath  string
	ReleasesPath string
}

func expectedLaravelPathList() []string {
	expectations := model.CoreLaravelPathExpectations()
	relativePaths := make([]string, 0, len(expectations))
	for _, expectation := range expectations {
		relativePaths = append(relativePaths, expectation.RelativePath)
	}

	return relativePaths
}

func (service SnapshotService) collectApplicationMetadata(ctx context.Context, rootPath string, resolvedPath string) (model.PathRecord, []model.PathRecord, model.EnvironmentInfo, []model.ArtifactRecord, []model.SourceMatch, model.DeploymentInfo, []model.Unknown) {
	var (
		rootRecord     model.PathRecord
		rootUnknown    *model.Unknown
		keyPaths       []model.PathRecord
		pathUnknowns   []model.Unknown
		environment    model.EnvironmentInfo
		envUnknowns    []model.Unknown
		artifacts      []model.ArtifactRecord
		artUnknowns    []model.Unknown
		sourceMatches  []model.SourceMatch
		srcUnknowns    []model.Unknown
		deploymentInfo model.DeploymentInfo
		depUnknowns    []model.Unknown
	)

	var wg sync.WaitGroup
	wg.Add(6)

	go func() {
		defer wg.Done()
		rootRecord, rootUnknown = service.inspectPathRecord(rootPath, ".")
	}()
	go func() {
		defer wg.Done()
		keyPaths, pathUnknowns = service.collectKeyPathRecords(rootPath)
	}()
	go func() {
		defer wg.Done()
		environment, envUnknowns = service.collectEnvironmentInfo(rootPath)
	}()
	go func() {
		defer wg.Done()
		artifacts, artUnknowns = service.collectArtifactRecords(ctx, rootPath)
	}()
	go func() {
		defer wg.Done()
		sourceMatches, srcUnknowns = service.collectFrameworkSourceMatches(ctx, rootPath)
	}()
	go func() {
		defer wg.Done()
		deploymentInfo, depUnknowns = service.collectDeploymentInfo(rootPath, resolvedPath)
	}()

	wg.Wait()

	unknowns := make([]model.Unknown, 0, len(pathUnknowns)+len(envUnknowns)+len(artUnknowns)+len(srcUnknowns)+len(depUnknowns)+1)
	if rootUnknown != nil {
		unknowns = append(unknowns, *rootUnknown)
	}
	unknowns = append(unknowns, pathUnknowns...)
	unknowns = append(unknowns, envUnknowns...)
	unknowns = append(unknowns, artUnknowns...)
	unknowns = append(unknowns, srcUnknowns...)
	unknowns = append(unknowns, depUnknowns...)

	return rootRecord, keyPaths, environment, artifacts, sourceMatches, deploymentInfo, unknowns
}

func (service SnapshotService) collectKeyPathRecords(rootPath string) ([]model.PathRecord, []model.Unknown) {
	expectations := model.CoreLaravelPathExpectations()
	records := make([]model.PathRecord, 0, len(expectations))
	unknowns := []model.Unknown{}

	for _, relativePath := range expectedLaravelPathList() {
		record, recordUnknown := service.inspectPathRecord(rootPath, relativePath)
		records = append(records, record)
		if recordUnknown != nil {
			unknowns = append(unknowns, *recordUnknown)
		}
	}

	model.SortPathRecords(records)

	return records, unknowns
}

func (service SnapshotService) collectEnvironmentInfo(rootPath string) (model.EnvironmentInfo, []model.Unknown) {
	envPath := filepath.Join(rootPath, ".env")
	envBytes, envUnknown := service.readOptionalFile(envPath, "Unable to read .env")
	if envUnknown != nil {
		return model.EnvironmentInfo{}, []model.Unknown{*envUnknown}
	}

	if len(envBytes) == 0 {
		return model.EnvironmentInfo{}, nil
	}

	return parseEnvironmentInfo(envBytes), nil
}

func parseEnvironmentInfo(envBytes []byte) model.EnvironmentInfo {
	environment := model.EnvironmentInfo{}

	for _, line := range strings.Split(string(envBytes), "\n") {
		trimmedLine := strings.TrimSpace(line)
		if trimmedLine == "" || strings.HasPrefix(trimmedLine, "#") {
			continue
		}

		trimmedLine = strings.TrimSpace(strings.TrimPrefix(trimmedLine, "export "))
		key, rawValue, foundSeparator := strings.Cut(trimmedLine, "=")
		if !foundSeparator {
			continue
		}

		normalizedKey := strings.TrimSpace(key)
		normalizedValue := normalizeEnvironmentValue(rawValue)

		switch normalizedKey {
		case "APP_DEBUG":
			environment.AppDebugDefined = true
			environment.AppDebugValue = normalizedValue
		case "APP_ENV":
			environment.AppEnvDefined = true
			environment.AppEnvValue = normalizedValue
		case "APP_KEY":
			environment.AppKeyDefined = normalizedValue != ""
			environment.AppKeyValue = normalizedValue
		case "DB_PASSWORD":
			environment.DBPasswordDefined = true
			environment.DBPasswordEmpty = normalizedValue == ""
		case "SESSION_SECURE_COOKIE":
			environment.SessionSecureCookieDefined = true
			environment.SessionSecureCookieValue = normalizedValue
		}
	}

	return environment
}

func normalizeEnvironmentValue(rawValue string) string {
	value := strings.TrimSpace(rawValue)
	if commentIndex := strings.Index(value, " #"); commentIndex >= 0 {
		value = value[:commentIndex]
		value = strings.TrimSpace(value)
	}

	if len(value) >= 2 {
		if value[0] == '"' && value[len(value)-1] == '"' {
			return value[1 : len(value)-1]
		}

		if value[0] == '\'' && value[len(value)-1] == '\'' {
			return value[1 : len(value)-1]
		}
	}

	return strings.TrimSpace(value)
}

func (service SnapshotService) collectArtifactRecords(ctx context.Context, rootPath string) ([]model.ArtifactRecord, []model.Unknown) {
	artifacts := []model.ArtifactRecord{}
	unknowns := []model.Unknown{}

	walkError := service.walkDirectory(rootPath, func(path string, directoryEntry fs.DirEntry, walkErr error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		if walkErr != nil {
			unknowns = append(unknowns, newPathUnknown(appDiscoveryCheckID, "Unable to inspect app artifact path", path, walkErr))
			if directoryEntry != nil && directoryEntry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		relativePath, err := filepath.Rel(rootPath, path)
		if err != nil || relativePath == "." {
			return nil
		}

		if shouldSkipArtifactDirectory(relativePath, directoryEntry) {
			return filepath.SkipDir
		}

		if directoryDepth(rootPath, path) > 4 {
			if directoryEntry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		artifactKind, withinPublicPath, uploadLikePath, isArtifact := classifyArtifactPath(relativePath, directoryEntry)
		if !isArtifact {
			return nil
		}

		pathRecord, recordUnknown := service.inspectPathRecord(rootPath, relativePath)
		if recordUnknown != nil {
			unknowns = append(unknowns, *recordUnknown)
			return nil
		}

		artifacts = append(artifacts, model.ArtifactRecord{
			Kind:             artifactKind,
			Path:             pathRecord,
			WithinPublicPath: withinPublicPath,
			UploadLikePath:   uploadLikePath,
		})

		if directoryEntry.IsDir() {
			return filepath.SkipDir
		}

		return nil
	})
	if walkError != nil && !errors.Is(walkError, context.Canceled) {
		unknowns = append(unknowns, newPathUnknown(appDiscoveryCheckID, "Artifact walk failed", rootPath, walkError))
	}

	model.SortArtifactRecords(artifacts)

	return artifacts, unknowns
}

func shouldSkipArtifactDirectory(relativePath string, directoryEntry fs.DirEntry) bool {
	if !directoryEntry.IsDir() {
		return false
	}

	normalizedRelativePath := filepath.ToSlash(relativePath)

	switch {
	case normalizedRelativePath == "vendor" || strings.HasPrefix(normalizedRelativePath, "vendor/"):
		return true
	case normalizedRelativePath == "node_modules" || strings.HasPrefix(normalizedRelativePath, "node_modules/"):
		return true
	case normalizedRelativePath == "storage/framework/cache" || strings.HasPrefix(normalizedRelativePath, "storage/framework/cache/"):
		return true
	default:
		return false
	}
}

func classifyArtifactPath(relativePath string, directoryEntry fs.DirEntry) (model.ArtifactKind, bool, bool, bool) {
	cleanRelativePath := filepath.ToSlash(filepath.Clean(relativePath))
	baseName := filepath.Base(cleanRelativePath)
	withinPublicPath := cleanRelativePath == "public" || strings.HasPrefix(cleanRelativePath, "public/")
	uploadLikePath := withinPublicPath && looksLikeUploadPath(cleanRelativePath)
	withinWritablePath := isWithinWritableAppPath(cleanRelativePath)

	switch {
	case isEnvironmentBackup(baseName):
		return model.ArtifactKindEnvironmentBackup, withinPublicPath, uploadLikePath, true
	case baseName == ".git" || baseName == ".svn":
		return model.ArtifactKindVersionControlPath, withinPublicPath, uploadLikePath, true
	case withinPublicPath && directoryEntry.Type()&fs.ModeSymlink != 0:
		return model.ArtifactKindPublicSymlink, true, uploadLikePath, true
	case withinPublicPath && matchesPublicAdminToolPath(cleanRelativePath, directoryEntry):
		return model.ArtifactKindPublicAdminTool, true, uploadLikePath, true
	case !directoryEntry.IsDir() && withinPublicPath && hasSensitivePublicFileExtension(baseName):
		return model.ArtifactKindPublicSensitiveFile, true, uploadLikePath, true
	case !directoryEntry.IsDir() && withinPublicPath && hasExecutablePHPExtension(baseName) && cleanRelativePath != "public/index.php":
		return model.ArtifactKindPublicPHPFile, true, uploadLikePath, true
	case withinWritablePath && directoryEntry.Type()&fs.ModeSymlink != 0:
		return model.ArtifactKindWritableSymlink, false, false, true
	case withinWritablePath && !directoryEntry.IsDir() && hasExecutablePHPExtension(baseName) && !isExpectedWritablePHPPath(cleanRelativePath):
		return model.ArtifactKindWritablePHPFile, false, false, true
	case withinWritablePath && !directoryEntry.IsDir() && hasArchiveFileExtension(baseName):
		return model.ArtifactKindWritableArchive, false, false, true
	default:
		return "", false, false, false
	}
}

func looksLikeUploadPath(relativePath string) bool {
	for _, marker := range []string{
		"public/storage/",
		"public/upload/",
		"public/uploads/",
		"public/media/",
		"public/files/",
	} {
		if strings.Contains(relativePath, marker) {
			return true
		}
	}

	return false
}

func isEnvironmentBackup(baseName string) bool {
	if baseName == ".env" || baseName == ".env.example" {
		return false
	}

	return strings.HasPrefix(baseName, ".env")
}

// hasFileExtension checks if a filename ends with one of the given extensions (case-insensitive).
func hasFileExtension(baseName string, extensions []string) bool {
	ext := filepath.Ext(baseName)
	for _, candidate := range extensions {
		if strings.EqualFold(ext, candidate) {
			return true
		}
	}
	return false
}

var sensitivePublicExtensions = []string{".sql", ".zip", ".tar", ".gz", ".tgz", ".log"}
var archiveExtensions = []string{".sql", ".zip", ".tar", ".gz", ".tgz", ".bak"}
var executablePHPExtensions = []string{".php", ".phtml", ".pht", ".phar", ".php3", ".php4", ".php5", ".php7", ".php8"}

func hasSensitivePublicFileExtension(baseName string) bool {
	return hasFileExtension(baseName, sensitivePublicExtensions)
}

func hasExecutablePHPExtension(baseName string) bool {
	return hasFileExtension(baseName, executablePHPExtensions)
}

func hasArchiveFileExtension(baseName string) bool {
	return hasFileExtension(baseName, archiveExtensions)
}

func isWithinWritableAppPath(relativePath string) bool {
	return relativePath == "storage" ||
		strings.HasPrefix(relativePath, "storage/") ||
		relativePath == "bootstrap/cache" ||
		strings.HasPrefix(relativePath, "bootstrap/cache/")
}

func (service SnapshotService) collectDeploymentInfo(rootPath string, resolvedPath string) (model.DeploymentInfo, []model.Unknown) {
	deploymentInfo := model.DeploymentInfo{CurrentPath: filepath.Clean(rootPath)}
	deploymentHint, unknowns := service.inferDeploymentLayout(rootPath, resolvedPath)
	if !deploymentHint.UsesReleaseLayout {
		return deploymentInfo, unknowns
	}

	deploymentInfo.UsesReleaseLayout = true
	if strings.TrimSpace(deploymentHint.CurrentPath) != "" {
		deploymentInfo.CurrentPath = deploymentHint.CurrentPath
	}
	deploymentInfo.ReleaseRoot = deploymentHint.ReleaseRoot
	deploymentInfo.SharedPath = deploymentHint.SharedPath

	if strings.TrimSpace(deploymentInfo.ReleaseRoot) == "" {
		return deploymentInfo, unknowns
	}

	releasePaths, err := service.expandConfigPattern(filepath.Join(deploymentInfo.ReleaseRoot, "*"))
	if err != nil {
		unknowns = append(unknowns, newPathUnknown(appDiscoveryCheckID, "Unable to inspect release layout", deploymentInfo.ReleaseRoot, err))
		return deploymentInfo, unknowns
	}

	for _, releasePath := range releasePaths {
		cleanReleasePath := filepath.Clean(releasePath)
		if deploymentHint.ActiveReleasePath != "" && cleanReleasePath == deploymentHint.ActiveReleasePath {
			continue
		}

		releaseInfo, statErr := service.statPath(cleanReleasePath)
		if statErr != nil || !releaseInfo.IsDir() {
			continue
		}

		record, unknown := service.inspectPathRecord(filepath.Dir(cleanReleasePath), filepath.Base(cleanReleasePath))
		if unknown != nil {
			unknowns = append(unknowns, *unknown)
			continue
		}

		deploymentInfo.PreviousReleases = append(deploymentInfo.PreviousReleases, record)
	}

	model.SortPathRecords(deploymentInfo.PreviousReleases)

	return deploymentInfo, unknowns
}

func (service SnapshotService) inferDeploymentLayout(rootPath string, resolvedPath string) (deploymentLayoutHint, []model.Unknown) {
	cleanRootPath := filepath.Clean(rootPath)
	cleanResolvedPath := filepath.Clean(strings.TrimSpace(resolvedPath))

	if hint, found := inferDeploymentLayoutFromResolvedPath(cleanRootPath, cleanResolvedPath); found {
		return hint, nil
	}

	if hint, found := service.inferDeploymentLayoutFromCurrentPath(cleanRootPath); found {
		return hint, nil
	}

	if hint, found := service.inferDeploymentLayoutFromReleasePath(cleanRootPath); found {
		return hint, nil
	}

	recipeConfigs, unknowns := service.collectDeploymentRecipeConfigs(cleanRootPath, cleanResolvedPath)
	for _, recipeConfig := range recipeConfigs {
		if hint, found := inferDeploymentLayoutFromRecipe(cleanRootPath, cleanResolvedPath, recipeConfig); found {
			return hint, unknowns
		}
	}

	return deploymentLayoutHint{}, unknowns
}

func inferDeploymentLayoutFromResolvedPath(currentPath string, resolvedPath string) (deploymentLayoutHint, bool) {
	if resolvedPath == "." || resolvedPath == "" || resolvedPath == currentPath {
		return deploymentLayoutHint{}, false
	}
	if filepath.Base(currentPath) != "current" || filepath.Base(filepath.Dir(resolvedPath)) != "releases" {
		return deploymentLayoutHint{}, false
	}

	releaseRoot := filepath.Dir(resolvedPath)
	deployRoot := filepath.Dir(releaseRoot)
	return deploymentLayoutHint{
		UsesReleaseLayout: true,
		CurrentPath:       currentPath,
		ReleaseRoot:       releaseRoot,
		SharedPath:        filepath.Join(deployRoot, "shared"),
		ActiveReleasePath: resolvedPath,
	}, true
}

func (service SnapshotService) inferDeploymentLayoutFromCurrentPath(currentPath string) (deploymentLayoutHint, bool) {
	if filepath.Base(currentPath) != "current" {
		return deploymentLayoutHint{}, false
	}

	deployRoot := filepath.Dir(currentPath)
	releaseRoot := filepath.Join(deployRoot, "releases")
	if !service.pathIsDirectory(releaseRoot) {
		return deploymentLayoutHint{}, false
	}

	return deploymentLayoutHint{
		UsesReleaseLayout: true,
		CurrentPath:       currentPath,
		ReleaseRoot:       releaseRoot,
		SharedPath:        filepath.Join(deployRoot, "shared"),
	}, true
}

func (service SnapshotService) inferDeploymentLayoutFromReleasePath(rootPath string) (deploymentLayoutHint, bool) {
	if filepath.Base(filepath.Dir(rootPath)) != "releases" {
		return deploymentLayoutHint{}, false
	}

	releaseRoot := filepath.Dir(rootPath)
	deployRoot := filepath.Dir(releaseRoot)
	currentPath := filepath.Join(deployRoot, "current")
	if !service.pathExists(currentPath) {
		return deploymentLayoutHint{}, false
	}

	return deploymentLayoutHint{
		UsesReleaseLayout: true,
		CurrentPath:       currentPath,
		ReleaseRoot:       releaseRoot,
		SharedPath:        filepath.Join(deployRoot, "shared"),
		ActiveReleasePath: rootPath,
	}, true
}

func inferDeploymentLayoutFromRecipe(rootPath string, resolvedPath string, recipeConfig deploymentRecipeConfig) (deploymentLayoutHint, bool) {
	deployPath := filepath.Clean(strings.TrimSpace(recipeConfig.DeployPath))
	if deployPath == "." || deployPath == "" {
		return deploymentLayoutHint{}, false
	}

	currentPath := deploymentPathValueOrDefault(recipeConfig.CurrentPath, filepath.Join(deployPath, "current"), deployPath)
	releaseRoot := deploymentPathValueOrDefault(recipeConfig.ReleaseRoot, "", deployPath)
	if releaseRoot == "" {
		releaseRoot = deploymentPathValueOrDefault(recipeConfig.ReleasesPath, filepath.Join(deployPath, "releases"), deployPath)
	}
	if releaseRoot == "" {
		releasePath := deploymentPathValueOrDefault(recipeConfig.ReleasePath, "", deployPath)
		if releasePath != "" {
			releaseRoot = filepath.Dir(strings.TrimSuffix(releasePath, string(filepath.Separator)+"{{release_name}}"))
		}
	}
	if releaseRoot == "" {
		releaseRoot = filepath.Join(deployPath, "releases")
	}
	sharedPath := deploymentPathValueOrDefault(recipeConfig.SharedPath, filepath.Join(deployPath, "shared"), deployPath)

	cleanRootPath := filepath.Clean(rootPath)
	cleanResolvedPath := filepath.Clean(strings.TrimSpace(resolvedPath))
	activeReleasePath := ""
	if cleanRootPath == currentPath || cleanResolvedPath == currentPath {
		if filepath.Base(filepath.Dir(cleanResolvedPath)) == "releases" {
			activeReleasePath = cleanResolvedPath
		}
	} else if cleanRootPath == filepath.Clean(releaseRoot) || cleanResolvedPath == filepath.Clean(releaseRoot) {
		return deploymentLayoutHint{}, false
	} else if pathIsWithinRoot(cleanRootPath, releaseRoot) {
		activeReleasePath = cleanRootPath
	} else if pathIsWithinRoot(cleanResolvedPath, releaseRoot) {
		activeReleasePath = cleanResolvedPath
	} else {
		return deploymentLayoutHint{}, false
	}

	return deploymentLayoutHint{
		UsesReleaseLayout: true,
		CurrentPath:       currentPath,
		ReleaseRoot:       releaseRoot,
		SharedPath:        sharedPath,
		ActiveReleasePath: activeReleasePath,
	}, true
}

func deploymentPathValueOrDefault(value string, fallback string, deployPath string) string {
	cleanValue := strings.TrimSpace(value)
	if cleanValue == "" {
		if strings.TrimSpace(fallback) == "" {
			return ""
		}
		return filepath.Clean(fallback)
	}

	replacedValue := strings.ReplaceAll(cleanValue, "{{deploy_path}}", deployPath)
	replacedValue = strings.ReplaceAll(replacedValue, "{{deployPath}}", deployPath)
	return filepath.Clean(replacedValue)
}

func pathIsWithinRoot(path string, root string) bool {
	cleanPath := filepath.Clean(strings.TrimSpace(path))
	cleanRoot := filepath.Clean(strings.TrimSpace(root))
	if cleanPath == "." || cleanPath == "" || cleanRoot == "." || cleanRoot == "" {
		return false
	}

	return cleanPath == cleanRoot || strings.HasPrefix(cleanPath, cleanRoot+string(filepath.Separator))
}

func (service SnapshotService) pathExists(path string) bool {
	_, err := service.statPath(path)
	return err == nil
}

func (service SnapshotService) pathIsDirectory(path string) bool {
	info, err := service.statPath(path)
	return err == nil && info.IsDir()
}

func (service SnapshotService) collectDeploymentRecipeConfigs(rootPath string, resolvedPath string) ([]deploymentRecipeConfig, []model.Unknown) {
	candidateRoots := []string{rootPath}
	if resolvedPath != "." && resolvedPath != "" && resolvedPath != rootPath {
		candidateRoots = append(candidateRoots, resolvedPath)
	}

	configs := []deploymentRecipeConfig{}
	unknowns := []model.Unknown{}
	visitedRecipePaths := map[string]bool{}

	for _, candidateRoot := range candidateRoots {
		for _, candidateName := range []string{"deploy.php", "deploy.yaml", "deploy.yml", "deployer.yaml", "deployer.yml"} {
			recipePath := filepath.Join(candidateRoot, candidateName)
			if visitedRecipePaths[recipePath] {
				continue
			}
			visitedRecipePaths[recipePath] = true

			recipeBytes, unknown := service.readOptionalFile(recipePath, "Unable to read deployment recipe")
			if unknown != nil {
				unknowns = append(unknowns, *unknown)
				continue
			}
			if len(recipeBytes) == 0 {
				continue
			}

			switch filepath.Ext(recipePath) {
			case ".php":
				phpConfigs, phpUnknowns := service.parseDeployerPHPRecipe(recipePath)
				configs = append(configs, phpConfigs...)
				unknowns = append(unknowns, phpUnknowns...)
			default:
				yamlConfigs, yamlUnknowns := service.parseDeployerYAMLRecipe(recipePath)
				configs = append(configs, yamlConfigs...)
				unknowns = append(unknowns, yamlUnknowns...)
			}
		}
	}

	return configs, unknowns
}

func (service SnapshotService) parseDeployerPHPRecipe(recipePath string) ([]deploymentRecipeConfig, []model.Unknown) {
	contents, unknowns := service.collectDeployerPHPRecipeContents(recipePath, map[string]bool{})
	if len(contents) == 0 {
		return nil, unknowns
	}

	mergedContents := strings.Join(contents, "\n")
	deployPaths := []string{}
	configValues := map[string]string{}
	for _, match := range deployerPHPSetRegex.FindAllStringSubmatch(mergedContents, -1) {
		if len(match) != 3 {
			continue
		}

		key := strings.TrimSpace(match[1])
		value := strings.TrimSpace(match[2])
		if key == "deploy_path" {
			deployPaths = append(deployPaths, value)
			continue
		}
		if _, found := configValues[key]; !found {
			configValues[key] = value
		}
	}

	configs := []deploymentRecipeConfig{}
	for _, deployPath := range uniqueStrings(deployPaths) {
		configs = append(configs, deploymentRecipeConfig{
			DeployPath:   deployPath,
			CurrentPath:  configValues["current_path"],
			ReleaseRoot:  configValues["release_root"],
			SharedPath:   configValues["shared_path"],
			ReleasePath:  configValues["release_path"],
			ReleasesPath: configValues["releases_path"],
		})
	}

	return configs, unknowns
}

func (service SnapshotService) collectDeployerPHPRecipeContents(recipePath string, visited map[string]bool) ([]string, []model.Unknown) {
	cleanRecipePath := filepath.Clean(recipePath)
	if visited[cleanRecipePath] {
		return nil, nil
	}
	visited[cleanRecipePath] = true

	recipeBytes, unknown := service.readOptionalFile(cleanRecipePath, "Unable to read deployment recipe")
	if unknown != nil {
		return nil, []model.Unknown{*unknown}
	}
	if len(recipeBytes) == 0 {
		return nil, nil
	}

	contents := []string{string(recipeBytes)}
	unknowns := []model.Unknown{}
	for _, match := range deployerPHPRequireRegex.FindAllStringSubmatch(string(recipeBytes), -1) {
		if len(match) != 2 {
			continue
		}

		requiredPath := filepath.Join(filepath.Dir(cleanRecipePath), strings.TrimPrefix(match[1], string(filepath.Separator)))
		childContents, childUnknowns := service.collectDeployerPHPRecipeContents(requiredPath, visited)
		contents = append(contents, childContents...)
		unknowns = append(unknowns, childUnknowns...)
	}

	return contents, unknowns
}

func (service SnapshotService) parseDeployerYAMLRecipe(recipePath string) ([]deploymentRecipeConfig, []model.Unknown) {
	recipeBytes, unknown := service.readOptionalFile(recipePath, "Unable to read deployment recipe")
	if unknown != nil {
		return nil, []model.Unknown{*unknown}
	}
	if len(recipeBytes) == 0 {
		return nil, nil
	}

	var recipe struct {
		Config map[string]string            `yaml:"config"`
		Hosts  map[string]map[string]string `yaml:"hosts"`
	}
	if err := yaml.Unmarshal(recipeBytes, &recipe); err != nil {
		return nil, []model.Unknown{newParseUnknown(appDiscoveryCheckID, "Unable to parse deployment recipe", recipePath, err)}
	}

	deployPaths := []string{}
	if deployPath := strings.TrimSpace(recipe.Config["deploy_path"]); deployPath != "" {
		deployPaths = append(deployPaths, deployPath)
	}
	for _, hostConfig := range recipe.Hosts {
		if deployPath := strings.TrimSpace(hostConfig["deploy_path"]); deployPath != "" {
			deployPaths = append(deployPaths, deployPath)
		}
	}

	configs := []deploymentRecipeConfig{}
	for _, deployPath := range uniqueStrings(deployPaths) {
		configs = append(configs, deploymentRecipeConfig{
			DeployPath:   deployPath,
			CurrentPath:  recipe.Config["current_path"],
			ReleaseRoot:  recipe.Config["release_root"],
			SharedPath:   recipe.Config["shared_path"],
			ReleasePath:  recipe.Config["release_path"],
			ReleasesPath: recipe.Config["releases_path"],
		})
	}

	return configs, nil
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	uniqueValues := make([]string, 0, len(values))
	for _, value := range values {
		cleanValue := strings.TrimSpace(value)
		if cleanValue == "" || seen[cleanValue] {
			continue
		}
		seen[cleanValue] = true
		uniqueValues = append(uniqueValues, cleanValue)
	}

	return uniqueValues
}

func isExpectedWritablePHPPath(relativePath string) bool {
	switch {
	case relativePath == "bootstrap/cache/config.php":
		return true
	case relativePath == "bootstrap/cache/packages.php":
		return true
	case relativePath == "bootstrap/cache/services.php":
		return true
	case relativePath == "bootstrap/cache/routes.php":
		return true
	case strings.HasPrefix(relativePath, "bootstrap/cache/routes-") && strings.HasSuffix(relativePath, ".php"):
		return true
	case strings.HasPrefix(relativePath, "storage/framework/views/") && strings.HasSuffix(relativePath, ".php"):
		return true
	default:
		return false
	}
}

func matchesPublicAdminToolPath(relativePath string, directoryEntry fs.DirEntry) bool {
	baseName := strings.ToLower(filepath.Base(relativePath))

	if !directoryEntry.IsDir() {
		if strings.HasPrefix(baseName, "adminer") && strings.HasSuffix(baseName, ".php") {
			return true
		}

		if strings.HasPrefix(baseName, "phpinfo") && strings.HasSuffix(baseName, ".php") {
			return true
		}
	}

	return baseName == "phpmyadmin"
}

func (service SnapshotService) inspectPathRecord(rootPath string, relativePath string) (model.PathRecord, *model.Unknown) {
	absolutePath := filepath.Join(rootPath, relativePath)
	return service.inspectAbsolutePathRecord(relativePath, absolutePath)
}

func (service SnapshotService) inspectAbsolutePathRecord(relativePath string, absolutePath string) (model.PathRecord, *model.Unknown) {
	record := model.PathRecord{
		RelativePath: relativePath,
		AbsolutePath: absolutePath,
	}

	pathInfo, err := service.lstatPath(absolutePath)
	switch {
	case err == nil:
	case errors.Is(err, fs.ErrNotExist):
		record.Inspected = true
		return record, nil
	default:
		unknown := newPathUnknown(appDiscoveryCheckID, "Unable to inspect app path", absolutePath, err)
		return record, &unknown
	}

	record.Inspected = true
	record.Exists = true
	record.PathKind = classifyPathKind(pathInfo)

	targetInfo := pathInfo
	if record.PathKind == model.PathKindSymlink {
		resolvedPath, resolveErr := service.resolveLinks(absolutePath)
		switch {
		case resolveErr == nil:
			record.ResolvedPath = resolvedPath
		case errors.Is(resolveErr, fs.ErrNotExist):
		default:
			unknown := newPathUnknown(appDiscoveryCheckID, "Unable to resolve app path symlink", absolutePath, resolveErr)
			return record, &unknown
		}

		resolvedInfo, statErr := service.statPath(absolutePath)
		switch {
		case statErr == nil:
			targetInfo = resolvedInfo
			record.TargetKind = classifyPathKind(resolvedInfo)
		case errors.Is(statErr, fs.ErrNotExist):
		default:
			unknown := newPathUnknown(appDiscoveryCheckID, "Unable to inspect app path target", absolutePath, statErr)
			return record, &unknown
		}
	}

	record.Permissions = uint32(targetInfo.Mode().Perm())
	record.UID, record.GID = ownershipFromFileInfo(targetInfo)
	record.OwnerName = service.lookupPrincipalName(record.UID, service.lookupUserName)
	record.GroupName = service.lookupPrincipalName(record.GID, service.lookupGroupName)
	if record.TargetKind == "" && record.PathKind != model.PathKindSymlink {
		record.TargetKind = record.PathKind
	}

	return record, nil
}

func classifyPathKind(fileInfo fs.FileInfo) model.PathKind {
	mode := fileInfo.Mode()

	switch {
	case mode&fs.ModeSymlink != 0:
		return model.PathKindSymlink
	case mode.IsRegular():
		return model.PathKindFile
	case mode.IsDir():
		return model.PathKindDirectory
	default:
		return model.PathKindOther
	}
}

func ownershipFromFileInfo(fileInfo fs.FileInfo) (uint32, uint32) {
	stat, ok := fileInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0
	}

	return stat.Uid, stat.Gid
}

func (service SnapshotService) lookupPrincipalName(identifier uint32, resolver func(string) (string, error)) string {
	if resolver == nil {
		return ""
	}

	name, err := resolver(strconv.FormatUint(uint64(identifier), 10))
	if err != nil {
		return ""
	}

	return strings.TrimSpace(name)
}
