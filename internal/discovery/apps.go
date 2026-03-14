package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"slices"
	"strings"

	"github.com/nagi1/larainspect/internal/model"
)

var requiredLaravelMarkerFiles = []string{
	"artisan",
	"bootstrap/app.php",
	"composer.json",
	"public/index.php",
}

var relevantComposerPackages = []string{
	"barryvdh/laravel-debugbar",
	"filament/filament",
	"inertiajs/inertia-laravel",
	"itsgoingd/clockwork",
	"laravel/fortify",
	"laravel/framework",
	"laravel/horizon",
	"laravel/octane",
	"laravel/telescope",
	"livewire/livewire",
	"spatie/laravel-ignition",
}

type composerManifest struct {
	Name       string            `json:"name"`
	Require    map[string]string `json:"require"`
	RequireDev map[string]string `json:"require-dev"`
}

type composerLockFile struct {
	Packages    []composerLockPackage `json:"packages"`
	PackagesDev []composerLockPackage `json:"packages-dev"`
}

type composerLockPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type installedPackagesFile struct {
	Packages []composerLockPackage
}

func (file *installedPackagesFile) UnmarshalJSON(data []byte) error {
	type packagesObject struct {
		Packages []composerLockPackage `json:"packages"`
	}

	var object packagesObject
	if err := json.Unmarshal(data, &object); err == nil && len(object.Packages) > 0 {
		file.Packages = object.Packages
		return nil
	}

	var packages []composerLockPackage
	if err := json.Unmarshal(data, &packages); err != nil {
		return err
	}

	file.Packages = packages
	return nil
}

func (service SnapshotService) discoverCandidateRootsFromScanRoot(ctx context.Context, scanRoot string) ([]string, []model.Unknown) {
	candidateRoots := make([]string, 0, 8)
	unknowns := make([]model.Unknown, 0, 4)
	seenRoots := map[string]struct{}{}
	cleanScanRoot := filepath.Clean(strings.TrimSpace(scanRoot))
	if cleanScanRoot == "." || cleanScanRoot == "" {
		return candidateRoots, unknowns
	}

	walkError := service.walkDirectory(cleanScanRoot, func(path string, directoryEntry fs.DirEntry, walkErr error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		if walkErr != nil {
			unknowns = append(unknowns, newPathUnknown(appDiscoveryCheckID, "Unable to inspect scan-root path", path, walkErr))
			if directoryEntry != nil && directoryEntry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		if directoryDepth(cleanScanRoot, path) > 4 {
			if directoryEntry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		candidateRoot, isCandidate := laravelCandidateRootForPath(path)
		if !isCandidate {
			return nil
		}

		cleanCandidateRoot := filepath.Clean(candidateRoot)
		if _, alreadySeen := seenRoots[cleanCandidateRoot]; alreadySeen {
			return nil
		}

		seenRoots[cleanCandidateRoot] = struct{}{}
		candidateRoots = append(candidateRoots, cleanCandidateRoot)
		return nil
	})
	if walkError != nil && !errors.Is(walkError, context.Canceled) {
		unknowns = append(unknowns, newPathUnknown(appDiscoveryCheckID, "Scan-root walk failed", cleanScanRoot, walkError))
	}

	slices.Sort(candidateRoots)

	return candidateRoots, unknowns
}

func (service SnapshotService) inspectLaravelApplication(ctx context.Context, rootPath string) (model.LaravelApp, []model.Unknown, bool) {
	unknowns := []model.Unknown{}

	rootInformation, err := service.statPath(rootPath)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			unknowns = append(unknowns, newPathUnknown(appDiscoveryCheckID, "Unable to inspect requested app path", rootPath, err))
		}
		return model.LaravelApp{}, unknowns, false
	}
	if !rootInformation.IsDir() {
		return model.LaravelApp{}, unknowns, false
	}

	markerFiles, markerUnknowns, hasAllMarkers := service.collectLaravelMarkerFiles(rootPath)
	unknowns = append(unknowns, markerUnknowns...)
	if !hasAllMarkers {
		return model.LaravelApp{}, unknowns, false
	}

	app := model.LaravelApp{
		RootPath:          rootPath,
		MarkerFiles:       markerFiles,
		Packages:          []model.PackageRecord{},
		InstalledPackages: map[string]string{},
	}

	resolvedPath, resolveErr := service.resolveLinks(rootPath)
	switch {
	case resolveErr == nil:
		app.ResolvedPath = resolvedPath
	case errors.Is(resolveErr, fs.ErrNotExist):
	case resolveErr != nil:
		unknowns = append(unknowns, newPathUnknown(appDiscoveryCheckID, "Unable to resolve app path symlinks", rootPath, resolveErr))
	}

	manifestPath := filepath.Join(rootPath, "composer.json")
	manifestBytes, manifestUnknown, ok := service.readRequiredFile(manifestPath, "Unable to read composer.json")
	if manifestUnknown != nil {
		unknowns = append(unknowns, *manifestUnknown)
	}
	if ok {
		manifest, parseErr := unmarshalJSON[composerManifest](manifestBytes)
		if parseErr != nil {
			unknowns = append(unknowns, newParseUnknown(appDiscoveryCheckID, "Unable to parse composer.json", manifestPath, parseErr))
		} else {
			app.AppName = manifest.Name
			app.PHPVersion = composerRequirement(manifest, "php")
			app.LaravelVersion = composerRequirement(manifest, "laravel/framework")
			app.Packages = mergePackageRecords(app.Packages, packageRecordsFromComposerManifest(manifest))
		}
	}

	lockPath := filepath.Join(rootPath, "composer.lock")
	service.mergeOptionalComposerPackages(&app, &unknowns, lockPath, "Unable to read composer.lock", "Unable to parse composer.lock", func(data []byte) ([]composerLockPackage, error) {
		lockFile, err := unmarshalJSON[composerLockFile](data)
		if err != nil {
			return nil, err
		}
		return append(lockFile.Packages, lockFile.PackagesDev...), nil
	}, "composer.lock")

	installedPackagesPath := filepath.Join(rootPath, "vendor/composer/installed.json")
	service.mergeOptionalComposerPackages(&app, &unknowns, installedPackagesPath, "Unable to read vendor/composer/installed.json", "Unable to parse vendor/composer/installed.json", func(data []byte) ([]composerLockPackage, error) {
		installedFile, err := unmarshalJSON[installedPackagesFile](data)
		if err != nil {
			return nil, err
		}
		return installedFile.Packages, nil
	}, "vendor/composer/installed.json")

	model.SortPackageRecords(app.Packages)
	app.LaravelVersion = packageVersionForName(app.Packages, "laravel/framework", app.LaravelVersion)

	rootRecord, keyPaths, environment, artifacts, sourceMatches, deploymentInfo, metadataUnknowns := service.collectApplicationMetadata(ctx, rootPath, app.ResolvedPath)
	app.RootRecord = rootRecord
	app.KeyPaths = keyPaths
	app.Environment = environment
	app.Artifacts = artifacts
	app.SourceMatches = sourceMatches
	app.Deployment = deploymentInfo
	unknowns = append(unknowns, metadataUnknowns...)

	return app, unknowns, true
}

func (service SnapshotService) collectLaravelMarkerFiles(rootPath string) ([]string, []model.Unknown, bool) {
	markerFiles := make([]string, 0, len(requiredLaravelMarkerFiles))
	unknowns := []model.Unknown{}

	for _, relativeMarkerPath := range requiredLaravelMarkerFiles {
		markerPath := filepath.Join(rootPath, relativeMarkerPath)
		_, err := service.statPath(markerPath)
		switch {
		case err == nil:
			markerFiles = append(markerFiles, relativeMarkerPath)
		case errors.Is(err, fs.ErrNotExist):
			return []string{}, unknowns, false
		default:
			unknowns = append(unknowns, newPathUnknown(appDiscoveryCheckID, "Unable to inspect Laravel marker file", markerPath, err))
			return []string{}, unknowns, false
		}
	}

	slices.Sort(markerFiles)

	return markerFiles, unknowns, true
}

func (service SnapshotService) readRequiredFile(path string, title string) ([]byte, *model.Unknown, bool) {
	fileBytes, err := service.readFile(path)
	if err == nil {
		return fileBytes, nil, true
	}

	unknown := newPathUnknown(appDiscoveryCheckID, title, path, err)
	return nil, &unknown, false
}

func (service SnapshotService) readOptionalFile(path string, title string) ([]byte, *model.Unknown) {
	fileBytes, err := service.readFile(path)
	switch {
	case err == nil:
		return fileBytes, nil
	case errors.Is(err, fs.ErrNotExist):
		return nil, nil
	default:
		unknown := newPathUnknown(appDiscoveryCheckID, title, path, err)
		return nil, &unknown
	}
}

// mergeOptionalComposerPackages reads an optional composer file, parses it, and merges
// the resulting package records into the app.
func (service SnapshotService) mergeOptionalComposerPackages(
	app *model.LaravelApp,
	unknowns *[]model.Unknown,
	path string,
	readTitle string,
	parseTitle string,
	parsePackages func([]byte) ([]composerLockPackage, error),
	source string,
) {
	fileBytes, fileUnknown := service.readOptionalFile(path, readTitle)
	if fileUnknown != nil {
		*unknowns = append(*unknowns, *fileUnknown)
	}
	if len(fileBytes) == 0 {
		return
	}

	packages, parseErr := parsePackages(fileBytes)
	if parseErr != nil {
		*unknowns = append(*unknowns, newParseUnknown(appDiscoveryCheckID, parseTitle, path, parseErr))
		return
	}

	app.Packages = mergePackageRecords(app.Packages, packageRecordsFromLockPackages(source, packages))
	mergeInstalledPackages(app, packages)
	app.LaravelVersion = packageVersionForName(app.Packages, "laravel/framework", app.LaravelVersion)
}

// unmarshalJSON is a generic JSON parser replacing the three identical parseComposer* functions.
func unmarshalJSON[T any](data []byte) (T, error) {
	var result T
	if err := json.Unmarshal(data, &result); err != nil {
		return result, err
	}
	return result, nil
}

// mergeInstalledPackages populates the full InstalledPackages map (name → version)
// from all packages in a composer source. Unlike Packages (which tracks only
// security-relevant packages), InstalledPackages catalogs every dependency
// for vulnerability intelligence.
func mergeInstalledPackages(app *model.LaravelApp, packages []composerLockPackage) {
	if app.InstalledPackages == nil {
		app.InstalledPackages = make(map[string]string, len(packages))
	}
	for _, pkg := range packages {
		name := strings.TrimSpace(pkg.Name)
		version := strings.TrimSpace(pkg.Version)
		if name == "" || version == "" {
			continue
		}
		app.InstalledPackages[name] = version
	}
}

func packageRecordsFromComposerManifest(manifest composerManifest) []model.PackageRecord {
	relevantPackages := map[string]model.PackageRecord{}

	for _, packageName := range relevantComposerPackages {
		if version, found := manifest.Require[packageName]; found {
			relevantPackages[packageName] = model.PackageRecord{Name: packageName, Version: version, Source: "composer.json"}
			continue
		}

		if version, found := manifest.RequireDev[packageName]; found {
			relevantPackages[packageName] = model.PackageRecord{Name: packageName, Version: version, Source: "composer.json"}
		}
	}

	return mapValues(relevantPackages)
}

func composerRequirement(manifest composerManifest, packageName string) string {
	if version, found := manifest.Require[packageName]; found {
		return version
	}
	if version, found := manifest.RequireDev[packageName]; found {
		return version
	}

	return ""
}

func packageVersionForName(packages []model.PackageRecord, packageName string, fallback string) string {
	for _, packageRecord := range packages {
		if packageRecord.Name == packageName && strings.TrimSpace(packageRecord.Version) != "" {
			return packageRecord.Version
		}
	}

	return strings.TrimSpace(fallback)
}

func packageRecordsFromLockPackages(source string, packages []composerLockPackage) []model.PackageRecord {
	relevantPackages := map[string]model.PackageRecord{}

	for _, packageDefinition := range packages {
		if !slices.Contains(relevantComposerPackages, packageDefinition.Name) {
			continue
		}

		relevantPackages[packageDefinition.Name] = model.PackageRecord{
			Name:    packageDefinition.Name,
			Version: packageDefinition.Version,
			Source:  source,
		}
	}

	return mapValues(relevantPackages)
}

func mergePackageRecords(existing []model.PackageRecord, updates []model.PackageRecord) []model.PackageRecord {
	mergedPackages := make(map[string]model.PackageRecord, len(existing)+len(updates))

	for _, packageRecord := range existing {
		mergedPackages[packageRecord.Name] = packageRecord
	}

	for _, packageRecord := range updates {
		mergedPackages[packageRecord.Name] = packageRecord
	}

	return mapValues(mergedPackages)
}

func mapValues(values map[string]model.PackageRecord) []model.PackageRecord {
	records := make([]model.PackageRecord, 0, len(values))
	for _, record := range values {
		records = append(records, record)
	}

	model.SortPackageRecords(records)

	return records
}

func laravelCandidateRootForPath(path string) (string, bool) {
	if filepath.Base(path) == "artisan" {
		return filepath.Dir(path), true
	}

	if filepath.ToSlash(path) == filepath.ToSlash(filepath.Join(filepath.Dir(filepath.Dir(path)), "bootstrap", "app.php")) {
		return filepath.Dir(filepath.Dir(path)), true
	}

	return "", false
}

func directoryDepth(root string, path string) int {
	relativePath, err := filepath.Rel(root, path)
	if err != nil || relativePath == "." {
		return 0
	}

	return strings.Count(filepath.ToSlash(relativePath), "/") + 1
}

func newPathUnknown(checkID string, title string, path string, err error) model.Unknown {
	return newUnknown(checkID, title, err.Error(), classifyFilesystemError(err), path)
}

func newParseUnknown(checkID string, title string, path string, err error) model.Unknown {
	return newUnknown(checkID, title, err.Error(), model.ErrorKindParseFailure, path)
}

func newRequestedAppUnknown(rootPath string) model.Unknown {
	return model.Unknown{
		ID:      buildUnknownID(appDiscoveryCheckID, "Requested app path is not a Laravel application", rootPath),
		CheckID: appDiscoveryCheckID,
		Title:   "Requested app path is not a Laravel application",
		Reason:  "The requested path does not include the required Laravel marker files.",
		Error:   model.ErrorKindNotEnoughData,
		Evidence: []model.Evidence{
			{Label: "path", Detail: rootPath},
		},
	}
}

func newUnknown(checkID string, title string, reason string, errorKind model.ErrorKind, path string) model.Unknown {
	return model.Unknown{
		ID:      buildUnknownID(checkID, title, path),
		CheckID: checkID,
		Title:   title,
		Reason:  reason,
		Error:   errorKind,
		Evidence: []model.Evidence{
			{Label: "path", Detail: path},
		},
	}
}

func buildUnknownID(checkID string, title string, path string) string {
	slug := strings.NewReplacer(" ", ".", "/", ".", "\\", ".", ":", ".", "-", ".", "__", "_").Replace(strings.ToLower(title))
	return fmt.Sprintf("%s.%s.%s", checkID, slug, strings.Trim(strings.ReplaceAll(filepath.Clean(path), string(filepath.Separator), "."), "."))
}

func classifyFilesystemError(err error) model.ErrorKind {
	switch {
	case errors.Is(err, fs.ErrPermission):
		return model.ErrorKindPermissionDenied
	case errors.Is(err, fs.ErrNotExist):
		return model.ErrorKindNotEnoughData
	default:
		return model.ErrorKindNotEnoughData
	}
}
