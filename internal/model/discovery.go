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
	RootPath      string           `json:"root_path"`
	ResolvedPath  string           `json:"resolved_path,omitempty"`
	AppName       string           `json:"app_name,omitempty"`
	MarkerFiles   []string         `json:"marker_files"`
	Packages      []PackageRecord  `json:"packages,omitempty"`
	KeyPaths      []PathRecord     `json:"key_paths,omitempty"`
	Environment   EnvironmentInfo  `json:"environment,omitempty"`
	Artifacts     []ArtifactRecord `json:"artifacts,omitempty"`
	SourceMatches []SourceMatch    `json:"source_matches,omitempty"`
	Deployment    DeploymentInfo   `json:"deployment,omitempty"`
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
	AppDebugDefined            bool   `json:"app_debug_defined,omitempty"`
	AppDebugValue              string `json:"app_debug_value,omitempty"`
	AppKeyDefined              bool   `json:"app_key_defined,omitempty"`
	AppKeyValue                string `json:"app_key_value,omitempty"`
	SessionSecureCookieDefined bool   `json:"session_secure_cookie_defined,omitempty"`
	SessionSecureCookieValue   string `json:"session_secure_cookie_value,omitempty"`
}

type ArtifactKind string

const (
	ArtifactKindEnvironmentBackup   ArtifactKind = "environment_backup"
	ArtifactKindPublicSensitiveFile ArtifactKind = "public_sensitive_file"
	ArtifactKindPublicPHPFile       ArtifactKind = "public_php_file"
	ArtifactKindPublicAdminTool     ArtifactKind = "public_admin_tool"
	ArtifactKindVersionControlPath  ArtifactKind = "version_control_path"
	ArtifactKindWritablePHPFile     ArtifactKind = "writable_php_file"
	ArtifactKindWritableSymlink     ArtifactKind = "writable_symlink"
	ArtifactKindWritableArchive     ArtifactKind = "writable_archive"
)

type ArtifactRecord struct {
	Kind             ArtifactKind `json:"kind"`
	Path             PathRecord   `json:"path"`
	WithinPublicPath bool         `json:"within_public_path,omitempty"`
	UploadLikePath   bool         `json:"upload_like_path,omitempty"`
}

type SourceMatch struct {
	RuleID       string `json:"rule_id"`
	RelativePath string `json:"relative_path"`
	Line         int    `json:"line,omitempty"`
	Detail       string `json:"detail,omitempty"`
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

type SupervisorProgram struct {
	ConfigPath string `json:"config_path"`
	Name       string `json:"name"`
	Command    string `json:"command,omitempty"`
	User       string `json:"user,omitempty"`
	Directory  string `json:"directory,omitempty"`
	AutoStart  string `json:"autostart,omitempty"`
}

type SupervisorHTTPServer struct {
	ConfigPath         string `json:"config_path"`
	Bind               string `json:"bind,omitempty"`
	Username           string `json:"username,omitempty"`
	PasswordConfigured bool   `json:"password_configured,omitempty"`
}

type SystemdUnit struct {
	Path             string   `json:"path"`
	Name             string   `json:"name"`
	Description      string   `json:"description,omitempty"`
	User             string   `json:"user,omitempty"`
	Group            string   `json:"group,omitempty"`
	WorkingDirectory string   `json:"working_directory,omitempty"`
	ExecStart        string   `json:"exec_start,omitempty"`
	NoNewPrivileges  string   `json:"no_new_privileges,omitempty"`
	ProtectSystem    string   `json:"protect_system,omitempty"`
	ReadWritePaths   []string `json:"read_write_paths,omitempty"`
	WantedBy         []string `json:"wanted_by,omitempty"`
}

type CronEntry struct {
	SourcePath string `json:"source_path"`
	Schedule   string `json:"schedule"`
	User       string `json:"user,omitempty"`
	Command    string `json:"command"`
}

type ListenerRecord struct {
	Protocol     string   `json:"protocol"`
	State        string   `json:"state,omitempty"`
	LocalAddress string   `json:"local_address,omitempty"`
	LocalPort    string   `json:"local_port,omitempty"`
	ProcessNames []string `json:"process_names,omitempty"`
}

type DeploymentInfo struct {
	UsesReleaseLayout bool         `json:"uses_release_layout,omitempty"`
	CurrentPath       string       `json:"current_path,omitempty"`
	ReleaseRoot       string       `json:"release_root,omitempty"`
	SharedPath        string       `json:"shared_path,omitempty"`
	PreviousReleases  []PathRecord `json:"previous_releases,omitempty"`
}

type SSHConfig struct {
	Path                   string `json:"path"`
	PermitRootLogin        string `json:"permit_root_login,omitempty"`
	PasswordAuthentication string `json:"password_authentication,omitempty"`
}

type SudoRule struct {
	Path        string   `json:"path"`
	Principal   string   `json:"principal"`
	RunAs       string   `json:"run_as,omitempty"`
	Commands    []string `json:"commands,omitempty"`
	NoPassword  bool     `json:"no_password,omitempty"`
	AllCommands bool     `json:"all_commands,omitempty"`
}

type FirewallSummary struct {
	Source  string `json:"source"`
	Enabled bool   `json:"enabled"`
	State   string `json:"state,omitempty"`
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
		{RelativePath: "storage/logs", Kind: PathKindDirectory, Required: false},
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

func SortSourceMatches(matches []SourceMatch) {
	sort.Slice(matches, func(leftIndex int, rightIndex int) bool {
		leftMatch := matches[leftIndex]
		rightMatch := matches[rightIndex]

		switch {
		case leftMatch.RelativePath != rightMatch.RelativePath:
			return leftMatch.RelativePath < rightMatch.RelativePath
		case leftMatch.Line != rightMatch.Line:
			return leftMatch.Line < rightMatch.Line
		default:
			return leftMatch.RuleID < rightMatch.RuleID
		}
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

func SortSupervisorPrograms(programs []SupervisorProgram) {
	sort.Slice(programs, func(leftIndex int, rightIndex int) bool {
		if programs[leftIndex].ConfigPath == programs[rightIndex].ConfigPath {
			return programs[leftIndex].Name < programs[rightIndex].Name
		}

		return programs[leftIndex].ConfigPath < programs[rightIndex].ConfigPath
	})
}

func SortSupervisorHTTPServers(servers []SupervisorHTTPServer) {
	sort.Slice(servers, func(leftIndex int, rightIndex int) bool {
		if servers[leftIndex].ConfigPath == servers[rightIndex].ConfigPath {
			return servers[leftIndex].Bind < servers[rightIndex].Bind
		}

		return servers[leftIndex].ConfigPath < servers[rightIndex].ConfigPath
	})
}

func SortSystemdUnits(units []SystemdUnit) {
	sort.Slice(units, func(leftIndex int, rightIndex int) bool {
		if units[leftIndex].Path == units[rightIndex].Path {
			return units[leftIndex].Name < units[rightIndex].Name
		}

		return units[leftIndex].Path < units[rightIndex].Path
	})
}

func SortCronEntries(entries []CronEntry) {
	sort.Slice(entries, func(leftIndex int, rightIndex int) bool {
		if entries[leftIndex].SourcePath == entries[rightIndex].SourcePath {
			if entries[leftIndex].Schedule == entries[rightIndex].Schedule {
				return entries[leftIndex].Command < entries[rightIndex].Command
			}

			return entries[leftIndex].Schedule < entries[rightIndex].Schedule
		}

		return entries[leftIndex].SourcePath < entries[rightIndex].SourcePath
	})
}

func SortListenerRecords(records []ListenerRecord) {
	sort.Slice(records, func(leftIndex int, rightIndex int) bool {
		leftRecord := records[leftIndex]
		rightRecord := records[rightIndex]

		switch {
		case leftRecord.Protocol != rightRecord.Protocol:
			return leftRecord.Protocol < rightRecord.Protocol
		case leftRecord.LocalPort != rightRecord.LocalPort:
			return leftRecord.LocalPort < rightRecord.LocalPort
		default:
			return leftRecord.LocalAddress < rightRecord.LocalAddress
		}
	})
}

func SortSSHConfigs(configs []SSHConfig) {
	sort.Slice(configs, func(leftIndex int, rightIndex int) bool {
		return configs[leftIndex].Path < configs[rightIndex].Path
	})
}

func SortSudoRules(rules []SudoRule) {
	sort.Slice(rules, func(leftIndex int, rightIndex int) bool {
		if rules[leftIndex].Path == rules[rightIndex].Path {
			return rules[leftIndex].Principal < rules[rightIndex].Principal
		}

		return rules[leftIndex].Path < rules[rightIndex].Path
	})
}

func SortFirewallSummaries(summaries []FirewallSummary) {
	sort.Slice(summaries, func(leftIndex int, rightIndex int) bool {
		return summaries[leftIndex].Source < summaries[rightIndex].Source
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
