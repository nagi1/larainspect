package model

import (
	"fmt"
	"sort"
)

type PackageRecord struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Source  string `json:"source,omitempty"`
}

type LaravelApp struct {
	RootPath     string           `json:"root_path"`
	ResolvedPath string           `json:"resolved_path,omitempty"`
	AppName      string           `json:"app_name,omitempty"`
	MarkerFiles  []string         `json:"marker_files"`
	Packages     []PackageRecord  `json:"packages,omitempty"`
	KeyPaths     []PathRecord     `json:"key_paths,omitempty"`
	Environment  EnvironmentInfo  `json:"environment,omitempty"`
	Artifacts    []ArtifactRecord `json:"artifacts,omitempty"`
}

func SortPackageRecords(records []PackageRecord) {
	sort.Slice(records, func(leftIndex int, rightIndex int) bool {
		if records[leftIndex].Name == records[rightIndex].Name {
			return records[leftIndex].Source < records[rightIndex].Source
		}

		return records[leftIndex].Name < records[rightIndex].Name
	})
}

type PathExpectation struct {
	RelativePath string   `json:"relative_path"`
	Kind         PathKind `json:"kind"`
	Required     bool     `json:"required"`
}

type PathKind string

const (
	PathKindFile      PathKind = "file"
	PathKindDirectory PathKind = "directory"
	PathKindSymlink   PathKind = "symlink"
	PathKindOther     PathKind = "other"
)

type PathRecord struct {
	RelativePath string   `json:"relative_path"`
	AbsolutePath string   `json:"absolute_path"`
	ResolvedPath string   `json:"resolved_path,omitempty"`
	PathKind     PathKind `json:"path_kind,omitempty"`
	TargetKind   PathKind `json:"target_kind,omitempty"`
	Inspected    bool     `json:"inspected"`
	Exists       bool     `json:"exists"`
	Permissions  uint32   `json:"permissions,omitempty"`
	UID          uint32   `json:"uid,omitempty"`
	GID          uint32   `json:"gid,omitempty"`
}

func (record PathRecord) EffectiveKind() PathKind {
	if record.TargetKind != "" {
		return record.TargetKind
	}

	return record.PathKind
}

func (record PathRecord) IsSymlink() bool {
	return record.PathKind == PathKindSymlink
}

func (record PathRecord) IsDirectory() bool {
	return record.Inspected && record.Exists && record.EffectiveKind() == PathKindDirectory
}

func (record PathRecord) IsRegularFile() bool {
	return record.Inspected && record.Exists && record.EffectiveKind() == PathKindFile
}

func (record PathRecord) ModeOctal() string {
	if !record.Inspected || !record.Exists {
		return ""
	}

	return fmt.Sprintf("%04o", record.Permissions)
}

func (record PathRecord) IsWorldWritable() bool {
	return record.Inspected && record.Exists && record.Permissions&0o002 != 0
}

func (record PathRecord) IsWorldReadable() bool {
	return record.Inspected && record.Exists && record.Permissions&0o004 != 0
}

type EnvironmentInfo struct {
	AppDebugDefined bool   `json:"app_debug_defined,omitempty"`
	AppDebugValue   string `json:"app_debug_value,omitempty"`
	AppKeyDefined   bool   `json:"app_key_defined,omitempty"`
	AppKeyValue     string `json:"app_key_value,omitempty"`
}

type ArtifactKind string

const (
	ArtifactKindEnvironmentBackup   ArtifactKind = "environment_backup"
	ArtifactKindPublicSensitiveFile ArtifactKind = "public_sensitive_file"
	ArtifactKindPublicPHPFile       ArtifactKind = "public_php_file"
	ArtifactKindVersionControlPath  ArtifactKind = "version_control_path"
)

type ArtifactRecord struct {
	Kind             ArtifactKind `json:"kind"`
	Path             PathRecord   `json:"path"`
	WithinPublicPath bool         `json:"within_public_path,omitempty"`
	UploadLikePath   bool         `json:"upload_like_path,omitempty"`
}

type NginxSite struct {
	ConfigPath              string   `json:"config_path"`
	ServerNames             []string `json:"server_names,omitempty"`
	Root                    string   `json:"root,omitempty"`
	IndexFiles              []string `json:"index_files,omitempty"`
	FastCGIPassTargets      []string `json:"fastcgi_pass_targets,omitempty"`
	GenericPHPLocations     []string `json:"generic_php_locations,omitempty"`
	FrontControllerPaths    []string `json:"front_controller_paths,omitempty"`
	HiddenDenyMatchers      []string `json:"hidden_deny_matchers,omitempty"`
	SensitiveDenyMatchers   []string `json:"sensitive_deny_matchers,omitempty"`
	UploadExecutionMatchers []string `json:"upload_execution_matchers,omitempty"`
	HasGenericPHPLocation   bool     `json:"has_generic_php_location,omitempty"`
	HasFrontControllerOnly  bool     `json:"has_front_controller_only,omitempty"`
	HiddenFilesDenied       bool     `json:"hidden_files_denied,omitempty"`
	SensitiveFilesDenied    bool     `json:"sensitive_files_denied,omitempty"`
	UploadExecutionAllowed  bool     `json:"upload_execution_allowed,omitempty"`
}

type PHPFPMPool struct {
	ConfigPath  string `json:"config_path"`
	Name        string `json:"name"`
	User        string `json:"user,omitempty"`
	Group       string `json:"group,omitempty"`
	Listen      string `json:"listen,omitempty"`
	ListenOwner string `json:"listen_owner,omitempty"`
	ListenGroup string `json:"listen_group,omitempty"`
	ListenMode  string `json:"listen_mode,omitempty"`
	ClearEnv    string `json:"clear_env,omitempty"`
}

func CoreLaravelPathExpectations() []PathExpectation {
	return []PathExpectation{
		{RelativePath: "app", Kind: PathKindDirectory, Required: true},
		{RelativePath: "bootstrap", Kind: PathKindDirectory, Required: true},
		{RelativePath: "bootstrap/cache", Kind: PathKindDirectory, Required: true},
		{RelativePath: "bootstrap/cache/config.php", Kind: PathKindFile, Required: false},
		{RelativePath: "config", Kind: PathKindDirectory, Required: true},
		{RelativePath: "database", Kind: PathKindDirectory, Required: true},
		{RelativePath: "public", Kind: PathKindDirectory, Required: true},
		{RelativePath: "public/index.php", Kind: PathKindFile, Required: true},
		{RelativePath: "public/storage", Kind: PathKindSymlink, Required: false},
		{RelativePath: "resources", Kind: PathKindDirectory, Required: true},
		{RelativePath: "routes", Kind: PathKindDirectory, Required: true},
		{RelativePath: "storage", Kind: PathKindDirectory, Required: true},
		{RelativePath: "vendor", Kind: PathKindDirectory, Required: true},
		{RelativePath: "artisan", Kind: PathKindFile, Required: true},
		{RelativePath: "composer.json", Kind: PathKindFile, Required: true},
		{RelativePath: "composer.lock", Kind: PathKindFile, Required: true},
		{RelativePath: ".env", Kind: PathKindFile, Required: false},
	}
}

func SortPathRecords(records []PathRecord) {
	sort.Slice(records, func(leftIndex int, rightIndex int) bool {
		return records[leftIndex].RelativePath < records[rightIndex].RelativePath
	})
}

func SortArtifactRecords(records []ArtifactRecord) {
	sort.Slice(records, func(leftIndex int, rightIndex int) bool {
		return records[leftIndex].Path.RelativePath < records[rightIndex].Path.RelativePath
	})
}

func SortNginxSites(sites []NginxSite) {
	sort.Slice(sites, func(leftIndex int, rightIndex int) bool {
		if sites[leftIndex].ConfigPath == sites[rightIndex].ConfigPath {
			return sites[leftIndex].Root < sites[rightIndex].Root
		}

		return sites[leftIndex].ConfigPath < sites[rightIndex].ConfigPath
	})
}

func SortPHPFPMPools(pools []PHPFPMPool) {
	sort.Slice(pools, func(leftIndex int, rightIndex int) bool {
		if pools[leftIndex].ConfigPath == pools[rightIndex].ConfigPath {
			return pools[leftIndex].Name < pools[rightIndex].Name
		}

		return pools[leftIndex].ConfigPath < pools[rightIndex].ConfigPath
	})
}

func (app LaravelApp) PathRecord(relativePath string) (PathRecord, bool) {
	for _, pathRecord := range app.KeyPaths {
		if pathRecord.RelativePath == relativePath {
			return pathRecord, true
		}
	}

	return PathRecord{}, false
}
