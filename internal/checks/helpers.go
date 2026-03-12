package checks

import (
	"fmt"
	"path/filepath"
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

	if pathRecord.ResolvedPath != "" && pathRecord.ResolvedPath != pathRecord.AbsolutePath {
		evidence = append(evidence, model.Evidence{Label: "resolved", Detail: pathRecord.ResolvedPath})
	}

	return evidence
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
