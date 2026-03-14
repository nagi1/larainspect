package discovery

import (
	"context"
	"errors"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/nagi1/larainspect/internal/model"
)

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
	unknowns := []model.Unknown{}
	cleanResolvedPath := filepath.Clean(strings.TrimSpace(resolvedPath))
	if cleanResolvedPath == "." || cleanResolvedPath == "" || cleanResolvedPath == deploymentInfo.CurrentPath {
		return deploymentInfo, unknowns
	}

	if filepath.Base(deploymentInfo.CurrentPath) != "current" || filepath.Base(filepath.Dir(cleanResolvedPath)) != "releases" {
		return deploymentInfo, unknowns
	}

	releaseRoot := filepath.Dir(cleanResolvedPath)
	sharedPath := filepath.Join(filepath.Dir(releaseRoot), "shared")
	deploymentInfo.UsesReleaseLayout = true
	deploymentInfo.ReleaseRoot = releaseRoot
	deploymentInfo.SharedPath = sharedPath

	releasePaths, err := service.expandConfigPattern(filepath.Join(releaseRoot, "*"))
	if err != nil {
		unknowns = append(unknowns, newPathUnknown(appDiscoveryCheckID, "Unable to inspect release layout", releaseRoot, err))
		return deploymentInfo, unknowns
	}

	for _, releasePath := range releasePaths {
		cleanReleasePath := filepath.Clean(releasePath)
		if cleanReleasePath == cleanResolvedPath {
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
