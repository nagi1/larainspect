package checks

import (
	"fmt"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/nagi1/larainspect/internal/model"
)

func buildFindingID(checkID string, suffix string, path string) string {
	cleanPath := strings.Trim(strings.ReplaceAll(filepath.Clean(path), string(filepath.Separator), "."), ".")
	if cleanPath == "" {
		return fmt.Sprintf("%s.%s", checkID, suffix)
	}

	return fmt.Sprintf("%s.%s.%s", checkID, suffix, cleanPath)
}

func appTarget(app model.LaravelApp) model.Target {
	return model.Target{Type: "path", Path: app.RootPath}
}

func pathTarget(pathRecord model.PathRecord) model.Target {
	return model.Target{Type: "path", Path: pathRecord.AbsolutePath}
}

func pathEvidence(pathRecord model.PathRecord) []model.Evidence {
	evidence := []model.Evidence{
		{Label: "path", Detail: pathRecord.AbsolutePath},
	}

	if pathRecord.ModeOctal() != "" {
		evidence = append(evidence, model.Evidence{Label: "mode", Detail: pathRecord.ModeOctal()})
	}

	if strings.TrimSpace(pathRecord.OwnerName) != "" {
		evidence = append(evidence, model.Evidence{Label: "owner", Detail: pathRecord.OwnerName})
	}

	if strings.TrimSpace(pathRecord.GroupName) != "" {
		evidence = append(evidence, model.Evidence{Label: "group", Detail: pathRecord.GroupName})
	}

	if pathRecord.ResolvedPath != "" && pathRecord.ResolvedPath != pathRecord.AbsolutePath {
		evidence = append(evidence, model.Evidence{Label: "resolved", Detail: pathRecord.ResolvedPath})
	}

	return evidence
}

func sourceMatchEvidence(app model.LaravelApp, sourceMatch model.SourceMatch) []model.Evidence {
	evidence := []model.Evidence{
		{Label: "source", Detail: filepath.Join(app.RootPath, sourceMatch.RelativePath)},
	}

	if sourceMatch.Line > 0 {
		evidence = append(evidence, model.Evidence{Label: "line", Detail: strconv.Itoa(sourceMatch.Line)})
	}

	if strings.TrimSpace(sourceMatch.Detail) != "" {
		evidence = append(evidence, model.Evidence{Label: "match", Detail: sourceMatch.Detail})
	}

	return evidence
}

func sourceMatchTarget(app model.LaravelApp, sourceMatch model.SourceMatch) model.Target {
	return model.Target{
		Type: "path",
		Path: filepath.Join(app.RootPath, sourceMatch.RelativePath),
	}
}

func boolFromEnvironmentValue(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func appCanonicalRoots(app model.LaravelApp) []string {
	roots := []string{filepath.Clean(app.RootPath)}
	if strings.TrimSpace(app.ResolvedPath) != "" {
		roots = append(roots, filepath.Clean(app.ResolvedPath))
	}

	return roots
}

func appExpectedPublicStorageTargets(app model.LaravelApp) []string {
	targets := []string{}
	for _, appRoot := range appCanonicalRoots(app) {
		targets = append(targets, filepath.Join(appRoot, "storage", "app", "public"))
	}
	if app.Deployment.UsesReleaseLayout && strings.TrimSpace(app.Deployment.CurrentPath) != "" && filepath.Base(filepath.Clean(app.Deployment.CurrentPath)) == "current" {
		targets = append(targets, filepath.Join(filepath.Dir(filepath.Clean(app.Deployment.CurrentPath)), "storage", "app", "public"))
	}
	if app.Deployment.UsesReleaseLayout && strings.TrimSpace(app.Deployment.SharedPath) != "" {
		targets = append(targets, filepath.Join(app.Deployment.SharedPath, "storage", "app", "public"))
	}

	return targets
}

func appPublicStoragePath(app model.LaravelApp) (model.PathRecord, bool) {
	publicStoragePath, found := app.PathRecord("public/storage")
	if !found || !publicStoragePath.Inspected || !publicStoragePath.Exists || !publicStoragePath.IsSymlink() {
		return model.PathRecord{}, false
	}

	return publicStoragePath, true
}

func appExpectedPublicStorageSymlink(app model.LaravelApp) (model.PathRecord, bool) {
	publicStoragePath, found := appPublicStoragePath(app)
	if !found || strings.TrimSpace(publicStoragePath.ResolvedPath) == "" {
		return model.PathRecord{}, false
	}
	if !publicStorageSymlinkLooksExpected(app, publicStoragePath) {
		return model.PathRecord{}, false
	}

	return publicStoragePath, true
}

func publicStorageSymlinkLooksExpected(app model.LaravelApp, publicStoragePath model.PathRecord) bool {
	if strings.TrimSpace(publicStoragePath.ResolvedPath) == "" {
		return false
	}

	return pathIsWithinAnyRoot(publicStoragePath.ResolvedPath, appExpectedPublicStorageTargets(app))
}

func pathIsWithinAnyRoot(path string, roots []string) bool {
	cleanPath := filepath.Clean(strings.TrimSpace(path))
	if cleanPath == "." || cleanPath == "" {
		return false
	}

	for _, root := range roots {
		cleanRoot := filepath.Clean(strings.TrimSpace(root))
		if cleanRoot == "." || cleanRoot == "" {
			continue
		}
		if cleanPath == cleanRoot || strings.HasPrefix(cleanPath, cleanRoot+string(filepath.Separator)) {
			return true
		}
	}

	return false
}

func appOwnsServedRoot(app model.LaravelApp, servedRoot string) bool {
	cleanServedRoot := filepath.Clean(strings.TrimSpace(servedRoot))
	if cleanServedRoot == "." || cleanServedRoot == "" {
		return false
	}

	for _, appRoot := range appCanonicalRoots(app) {
		if cleanServedRoot == appRoot || cleanServedRoot == filepath.Join(appRoot, "public") {
			return true
		}

		if strings.HasPrefix(cleanServedRoot, appRoot+string(filepath.Separator)) {
			return true
		}
	}

	return false
}

func appUsesPublicRoot(app model.LaravelApp, servedRoot string) bool {
	cleanServedRoot := filepath.Clean(strings.TrimSpace(servedRoot))
	for _, appRoot := range appCanonicalRoots(app) {
		if cleanServedRoot == filepath.Join(appRoot, "public") {
			return true
		}
	}

	return false
}

func appUsesPackage(app model.LaravelApp, packageName string) bool {
	_, found := packageRecordForApp(app, packageName)
	return found
}

func packageRecordForApp(app model.LaravelApp, packageName string) (model.PackageRecord, bool) {
	for _, packageRecord := range app.Packages {
		if packageRecord.Name == packageName {
			return packageRecord, true
		}
	}

	return model.PackageRecord{}, false
}

func sourceMatchesForRule(app model.LaravelApp, ruleID string) []model.SourceMatch {
	matches := []model.SourceMatch{}
	for _, sourceMatch := range app.SourceMatches {
		if sourceMatch.RuleID == ruleID {
			matches = append(matches, sourceMatch)
		}
	}

	return matches
}

func sourceMatchesWithPrefix(app model.LaravelApp, rulePrefix string) []model.SourceMatch {
	matches := []model.SourceMatch{}
	for _, sourceMatch := range app.SourceMatches {
		if strings.HasPrefix(sourceMatch.RuleID, rulePrefix) {
			matches = append(matches, sourceMatch)
		}
	}

	return matches
}

func sourceMatchesForRuleAtRelativePath(app model.LaravelApp, ruleID string, relativePath string) []model.SourceMatch {
	matches := []model.SourceMatch{}
	for _, sourceMatch := range app.SourceMatches {
		if sourceMatch.RuleID != ruleID || sourceMatch.RelativePath != relativePath {
			continue
		}

		matches = append(matches, sourceMatch)
	}

	return matches
}

func uniqueRelativePathsForMatches(matches []model.SourceMatch) []string {
	relativePaths := make([]string, 0, len(matches))
	for _, sourceMatch := range matches {
		relativePaths = append(relativePaths, sourceMatch.RelativePath)
	}

	slices.Sort(relativePaths)
	return slices.Compact(relativePaths)
}

func parseOctalMode(value string) (uint32, bool) {
	trimmedValue := strings.TrimSpace(strings.TrimPrefix(value, "0"))
	if trimmedValue == "" {
		return 0, false
	}

	parsedValue, err := strconv.ParseUint(trimmedValue, 8, 32)
	if err != nil {
		return 0, false
	}

	return uint32(parsedValue), true
}
