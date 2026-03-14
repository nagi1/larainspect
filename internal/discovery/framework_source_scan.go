package discovery

import (
	"context"
	"errors"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/nagi1/larainspect/internal/model"
)

const (
	maxFrameworkSourceFileBytes         = 256 * 1024
	maxFrameworkSourceFilesPerDirectory = 48
	maxFrameworkSourceDirectoryDepth    = 4
)

func (service SnapshotService) collectFrameworkSourceMatches(ctx context.Context, rootPath string) ([]model.SourceMatch, []model.Unknown) {
	matches := make([]model.SourceMatch, 0, len(frameworkHeuristicOptionalFiles)+16)
	unknowns := make([]model.Unknown, 0, 4)
	scannedRelativePaths := map[string]struct{}{}

	for _, relativePath := range frameworkHeuristicOptionalFiles {
		fileMatches, fileUnknown := service.collectSourceMatchesFromOptionalFile(rootPath, relativePath, scannedRelativePaths)
		matches = append(matches, fileMatches...)
		if fileUnknown != nil {
			unknowns = append(unknowns, *fileUnknown)
		}
	}

	for _, relativeDirectoryPath := range frameworkHeuristicOptionalDirectories {
		directoryMatches, directoryUnknowns := service.collectSourceMatchesFromOptionalDirectory(ctx, rootPath, relativeDirectoryPath, scannedRelativePaths)
		matches = append(matches, directoryMatches...)
		unknowns = append(unknowns, directoryUnknowns...)
	}

	ruleMatches, ruleUnknowns := service.collectConfiguredRuleMatches(ctx, rootPath)
	matches = append(matches, ruleMatches...)
	unknowns = append(unknowns, ruleUnknowns...)

	model.SortSourceMatches(matches)

	return matches, unknowns
}

func (service SnapshotService) collectSourceMatchesFromOptionalDirectory(
	ctx context.Context,
	rootPath string,
	relativeDirectoryPath string,
	scannedRelativePaths map[string]struct{},
) ([]model.SourceMatch, []model.Unknown) {
	absoluteDirectoryPath := filepath.Join(rootPath, relativeDirectoryPath)
	directoryInfo, err := service.statPath(absoluteDirectoryPath)
	switch {
	case err == nil:
	case errors.Is(err, fs.ErrNotExist):
		return nil, nil
	default:
		unknown := newPathUnknown(appDiscoveryCheckID, "Unable to inspect framework source directory", absoluteDirectoryPath, err)
		return nil, []model.Unknown{unknown}
	}

	if !directoryInfo.IsDir() {
		return nil, nil
	}

	matches := []model.SourceMatch{}
	unknowns := []model.Unknown{}
	scannedFileCount := 0

	walkErr := service.walkDirectory(absoluteDirectoryPath, func(path string, directoryEntry fs.DirEntry, walkErr error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		if walkErr != nil {
			unknowns = append(unknowns, newPathUnknown(appDiscoveryCheckID, "Unable to inspect framework source path", path, walkErr))
			if directoryEntry != nil && directoryEntry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		if directoryEntry.IsDir() {
			if directoryDepth(absoluteDirectoryPath, path) > maxFrameworkSourceDirectoryDepth {
				return filepath.SkipDir
			}
			return nil
		}

		if filepath.Ext(path) != ".php" {
			return nil
		}

		if scannedFileCount >= maxFrameworkSourceFilesPerDirectory {
			return fs.SkipAll
		}

		relativePath, relErr := filepath.Rel(rootPath, path)
		if relErr != nil {
			return nil
		}

		fileMatches, fileUnknown := service.collectSourceMatchesFromOptionalFile(rootPath, relativePath, scannedRelativePaths)
		matches = append(matches, fileMatches...)
		if fileUnknown != nil {
			unknowns = append(unknowns, *fileUnknown)
		}
		scannedFileCount++

		return nil
	})
	switch {
	case walkErr == nil:
	case errors.Is(walkErr, context.Canceled), errors.Is(walkErr, fs.SkipAll):
	default:
		unknowns = append(unknowns, newPathUnknown(appDiscoveryCheckID, "Framework source walk failed", absoluteDirectoryPath, walkErr))
	}

	return matches, unknowns
}

func (service SnapshotService) collectSourceMatchesFromOptionalFile(
	rootPath string,
	relativePath string,
	scannedRelativePaths map[string]struct{},
) ([]model.SourceMatch, *model.Unknown) {
	cleanRelativePath := filepath.Clean(relativePath)
	if _, alreadyScanned := scannedRelativePaths[cleanRelativePath]; alreadyScanned {
		return nil, nil
	}
	scannedRelativePaths[cleanRelativePath] = struct{}{}

	absolutePath := filepath.Join(rootPath, cleanRelativePath)
	fileInfo, err := service.statPath(absolutePath)
	switch {
	case err == nil:
	case errors.Is(err, fs.ErrNotExist):
		return nil, nil
	default:
		unknown := newPathUnknown(appDiscoveryCheckID, "Unable to inspect framework source file", absolutePath, err)
		return nil, &unknown
	}

	if fileInfo.IsDir() || fileInfo.Size() > maxFrameworkSourceFileBytes {
		return nil, nil
	}

	fileBytes, fileUnknown := service.readOptionalFile(absolutePath, "Unable to read framework source file")
	if fileUnknown != nil {
		return nil, fileUnknown
	}
	if len(fileBytes) == 0 {
		return nil, nil
	}

	return detectFrameworkHeuristicMatches(filepath.ToSlash(cleanRelativePath), string(fileBytes)), nil
}

func detectFrameworkSourceMatches(relativePath string, fileContents string) []model.SourceMatch {
	matches := detectFrameworkHeuristicMatches(relativePath, fileContents)
	matches = append(matches, defaultFrameworkRuleEngine().MatchFile(relativePath, fileContents)...)
	model.SortSourceMatches(matches)

	return matches
}

func detectFrameworkHeuristicMatches(relativePath string, fileContents string) []model.SourceMatch {
	sanitizedFileContents := stripPHPCommentsPreservingNewlines(fileContents)
	matches := []model.SourceMatch{}
	matches = append(matches, detectLaravelFrameworkSourceMatches(relativePath, sanitizedFileContents)...)
	matches = append(matches, detectLivewireFrameworkSourceMatches(relativePath, sanitizedFileContents)...)
	matches = append(matches, detectFilamentFrameworkSourceMatches(relativePath, sanitizedFileContents)...)
	matches = append(matches, detectFortifyFrameworkSourceMatches(relativePath, sanitizedFileContents)...)
	matches = append(matches, detectInertiaFrameworkSourceMatches(relativePath, sanitizedFileContents)...)
	model.SortSourceMatches(matches)

	return matches
}

func (service SnapshotService) collectConfiguredRuleMatches(ctx context.Context, rootPath string) ([]model.SourceMatch, []model.Unknown) {
	matches, issues := service.ruleEngine.ScanRoot(ctx, rootPath)
	unknowns := make([]model.Unknown, 0, len(issues))

	for _, issue := range issues {
		unknown := newPathUnknown(appDiscoveryCheckID, "Unable to evaluate source rules", issue.Path, issue)
		if strings.TrimSpace(issue.RuleID) != "" {
			unknown.Evidence = append(unknown.Evidence, model.Evidence{Label: "rule_id", Detail: issue.RuleID})
		}
		unknowns = append(unknowns, unknown)
	}

	return matches, compactUnknowns(unknowns)
}
