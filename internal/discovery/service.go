package discovery

import (
	"context"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/nagi1/larainspect/internal/model"
)

const (
	appDiscoveryCheckID = "discovery.apps"
)

var knownToolNames = []string{
	"cat",
	"crontab",
	"firewall-cmd",
	"find",
	"hostname",
	"ip",
	"iptables",
	"ls",
	"nginx",
	"nft",
	"php-fpm",
	"php-fpm8.0",
	"php-fpm8.1",
	"php-fpm8.2",
	"php-fpm8.3",
	"php-fpm8.4",
	"ps",
	"pwd",
	"readlink",
	"ss",
	"stat",
	"systemctl",
	"tail",
	"uname",
	"ufw",
	"whoami",
}

type Service interface {
	Discover(context.Context, model.ExecutionContext) (model.Snapshot, []model.Unknown, error)
}

type SnapshotService struct {
	lookPath           func(string) (string, error)
	readFile           func(string) ([]byte, error)
	statPath           func(string) (fs.FileInfo, error)
	lstatPath          func(string) (fs.FileInfo, error)
	globPaths          func(string) ([]string, error)
	walkDirectory      func(string, fs.WalkDirFunc) error
	resolveLinks       func(string) (string, error)
	runCommand         func(context.Context, model.CommandRequest) (model.CommandResult, error)
	nginxPatterns      []string
	phpFPMPatterns     []string
	supervisorPatterns []string
	systemdPatterns    []string
	cronPatterns       []string
	sshPatterns        []string
	sudoersPatterns    []string
	discoverNginx      bool
	discoverPHPFPM     bool
	discoverSupervisor bool
	discoverSystemd    bool
	discoverCron       bool
	discoverListeners  bool
	discoverSSH        bool
	discoverSudo       bool
	discoverFirewall   bool
}

func NewService() SnapshotService {
	return SnapshotService{
		lookPath:      exec.LookPath,
		readFile:      os.ReadFile,
		statPath:      os.Stat,
		lstatPath:     os.Lstat,
		globPaths:     filepath.Glob,
		walkDirectory: filepath.WalkDir,
		resolveLinks:  filepath.EvalSymlinks,
		runCommand: func(context.Context, model.CommandRequest) (model.CommandResult, error) {
			return model.CommandResult{}, fs.ErrPermission
		},
		nginxPatterns: []string{
			"/etc/nginx/nginx.conf",
			"/etc/nginx/conf.d/*.conf",
			"/etc/nginx/sites-enabled/*",
			"/usr/local/etc/nginx/nginx.conf",
			"/usr/local/etc/nginx/conf.d/*.conf",
			"/usr/local/etc/nginx/servers/*",
		},
		phpFPMPatterns: []string{
			"/etc/php/*/fpm/pool.d/*.conf",
			"/etc/php-fpm.d/*.conf",
			"/usr/local/etc/php-fpm.d/*.conf",
		},
		supervisorPatterns: []string{
			"/etc/supervisor/supervisord.conf",
			"/etc/supervisor/conf.d/*.conf",
			"/etc/supervisord.conf",
			"/etc/supervisord.d/*.ini",
		},
		systemdPatterns: []string{
			"/etc/systemd/system/*.service",
			"/usr/lib/systemd/system/*.service",
			"/lib/systemd/system/*.service",
		},
		cronPatterns: []string{
			"/etc/crontab",
			"/etc/cron.d/*",
			"/etc/cron.daily/*",
			"/var/spool/cron/*",
			"/var/spool/cron/crontabs/*",
		},
		sshPatterns: []string{
			"/etc/ssh/sshd_config",
			"/etc/ssh/sshd_config.d/*.conf",
		},
		sudoersPatterns: []string{
			"/etc/sudoers",
			"/etc/sudoers.d/*",
		},
		discoverNginx:      true,
		discoverPHPFPM:     true,
		discoverSupervisor: true,
		discoverSystemd:    true,
		discoverCron:       true,
		discoverListeners:  true,
		discoverSSH:        true,
		discoverSudo:       true,
		discoverFirewall:   true,
	}
}

func NewServiceForAudit(config model.AuditConfig) SnapshotService {
	service := NewService()
	service.nginxPatterns = config.NormalizedNginxConfigPatterns()
	service.phpFPMPatterns = config.NormalizedPHPFPMPoolPatterns()
	service.supervisorPatterns = config.NormalizedSupervisorConfigPatterns()
	service.systemdPatterns = config.NormalizedSystemdUnitPatterns()
	service.discoverNginx = config.ShouldDiscoverNginx()
	service.discoverPHPFPM = config.ShouldDiscoverPHPFPM()
	service.discoverSupervisor = config.ShouldDiscoverSupervisor()
	service.discoverSystemd = config.ShouldDiscoverSystemd()

	return service
}

type NoopService struct{}

func (service NoopService) Discover(_ context.Context, execution model.ExecutionContext) (model.Snapshot, []model.Unknown, error) {
	return model.Snapshot{
		Host:  execution.Host,
		Tools: execution.Tools,
	}, nil, nil
}

func (service SnapshotService) Discover(ctx context.Context, execution model.ExecutionContext) (model.Snapshot, []model.Unknown, error) {
	snapshot := model.Snapshot{
		Host:  execution.Host,
		Tools: service.discoverToolAvailability(),
		Apps:  []model.LaravelApp{},
	}
	if execution.Commands != nil {
		service.runCommand = execution.Commands.Run
	}
	unknowns := []model.Unknown{}

	if execution.Config.ShouldDiscoverApplications() {
		discoveredApps, discoveryUnknowns := service.discoverLaravelApplications(ctx, execution.Config)
		snapshot.Apps = discoveredApps
		unknowns = append(unknowns, discoveryUnknowns...)
	}

	service.appendServiceConfigs(ctx, execution.Config, &snapshot, &unknowns)

	return snapshot, unknowns, nil
}

func (service SnapshotService) discoverToolAvailability() model.ToolAvailability {
	tools := make(model.ToolAvailability, len(knownToolNames))

	for _, toolName := range knownToolNames {
		_, err := service.lookPath(toolName)
		tools[toolName] = err == nil
	}

	return tools
}

func (service SnapshotService) appendServiceConfigs(ctx context.Context, config model.AuditConfig, snapshot *model.Snapshot, unknowns *[]model.Unknown) {
	nginxSites := []model.NginxSite{}
	nginxUnknowns := []model.Unknown{}
	if service.discoverNginx {
		nginxSites, nginxUnknowns = service.discoverNginxSites()
	}

	phpFPMPools := []model.PHPFPMPool{}
	phpFPMUnknowns := []model.Unknown{}
	if service.discoverPHPFPM {
		phpFPMPools, phpFPMUnknowns = service.discoverPHPFPMPools()
	}

	supervisorPrograms := []model.SupervisorProgram{}
	supervisorHTTPServers := []model.SupervisorHTTPServer{}
	supervisorUnknowns := []model.Unknown{}
	if service.discoverSupervisor {
		supervisorPrograms, supervisorHTTPServers, supervisorUnknowns = service.discoverSupervisorConfigs()
	}

	systemdUnits := []model.SystemdUnit{}
	systemdUnknowns := []model.Unknown{}
	if service.discoverSystemd {
		systemdUnits, systemdUnknowns = service.discoverSystemdUnits()
	}

	cronEntries := []model.CronEntry{}
	cronUnknowns := []model.Unknown{}
	if service.discoverCron {
		cronEntries, cronUnknowns = service.discoverCronEntries()
	}

	listeners := []model.ListenerRecord{}
	listenerUnknowns := []model.Unknown{}
	shouldDiscoverListeners := service.discoverListeners && (config.Scope == model.ScanScopeHost || (config.Scope != model.ScanScopeApp && len(snapshot.Apps) > 0))
	if shouldDiscoverListeners {
		listeners, listenerUnknowns = service.discoverListenersFromCommand(ctx)
	}

	sshConfigs := []model.SSHConfig{}
	sshUnknowns := []model.Unknown{}
	if service.discoverSSH && config.Scope == model.ScanScopeHost {
		sshConfigs, sshUnknowns = service.discoverSSHConfigs()
	}

	sudoRules := []model.SudoRule{}
	sudoUnknowns := []model.Unknown{}
	if service.discoverSudo && config.Scope == model.ScanScopeHost {
		sudoRules, sudoUnknowns = service.discoverSudoRules()
	}

	firewallSummaries := []model.FirewallSummary{}
	firewallUnknowns := []model.Unknown{}
	if service.discoverFirewall && config.Scope == model.ScanScopeHost {
		firewallSummaries, firewallUnknowns = service.discoverFirewallSummaries(ctx)
	}

	snapshot.NginxSites = nginxSites
	snapshot.PHPFPMPools = phpFPMPools
	snapshot.SupervisorPrograms = supervisorPrograms
	snapshot.SupervisorHTTPServers = supervisorHTTPServers
	snapshot.SystemdUnits = systemdUnits
	snapshot.CronEntries = cronEntries
	snapshot.Listeners = listeners
	snapshot.SSHConfigs = sshConfigs
	snapshot.SudoRules = sudoRules
	snapshot.FirewallSummaries = firewallSummaries
	*unknowns = append(*unknowns, nginxUnknowns...)
	*unknowns = append(*unknowns, phpFPMUnknowns...)
	*unknowns = append(*unknowns, supervisorUnknowns...)
	*unknowns = append(*unknowns, systemdUnknowns...)
	*unknowns = append(*unknowns, cronUnknowns...)
	*unknowns = append(*unknowns, listenerUnknowns...)
	*unknowns = append(*unknowns, sshUnknowns...)
	*unknowns = append(*unknowns, sudoUnknowns...)
	*unknowns = append(*unknowns, firewallUnknowns...)
}

func (service SnapshotService) discoverLaravelApplications(ctx context.Context, config model.AuditConfig) ([]model.LaravelApp, []model.Unknown) {
	discoveredApps := []model.LaravelApp{}
	unknowns := []model.Unknown{}
	seenRoots := map[string]struct{}{}

	if explicitAppPath := strings.TrimSpace(config.AppPath); explicitAppPath != "" {
		service.appendRequestedApplication(ctx, &discoveredApps, &unknowns, seenRoots, explicitAppPath)
	}

	for _, scanRoot := range config.EffectiveScanRoots() {
		candidateRoots, scanUnknowns := service.discoverCandidateRootsFromScanRoot(ctx, scanRoot)
		unknowns = append(unknowns, scanUnknowns...)

		for _, candidateRoot := range candidateRoots {
			service.appendDiscoveredApplication(ctx, &discoveredApps, &unknowns, seenRoots, candidateRoot)
		}
	}

	slices.SortFunc(discoveredApps, func(leftApp model.LaravelApp, rightApp model.LaravelApp) int {
		return strings.Compare(leftApp.RootPath, rightApp.RootPath)
	})

	return discoveredApps, unknowns
}

func (service SnapshotService) appendRequestedApplication(
	ctx context.Context,
	discoveredApps *[]model.LaravelApp,
	unknowns *[]model.Unknown,
	seenRoots map[string]struct{},
	rootPath string,
) {
	app, appUnknowns, isLaravelApp, alreadySeen := service.inspectAndTrackApplication(ctx, seenRoots, rootPath)
	*unknowns = append(*unknowns, appUnknowns...)

	if alreadySeen || isLaravelApp {
		if isLaravelApp {
			*discoveredApps = append(*discoveredApps, app)
		}
		return
	}

	if len(appUnknowns) != 0 {
		return
	}

	*unknowns = append(*unknowns, newRequestedAppUnknown(filepath.Clean(strings.TrimSpace(rootPath))))
}

func (service SnapshotService) appendDiscoveredApplication(
	ctx context.Context,
	discoveredApps *[]model.LaravelApp,
	unknowns *[]model.Unknown,
	seenRoots map[string]struct{},
	rootPath string,
) {
	app, appUnknowns, isLaravelApp, alreadySeen := service.inspectAndTrackApplication(ctx, seenRoots, rootPath)
	*unknowns = append(*unknowns, appUnknowns...)
	if alreadySeen || !isLaravelApp {
		return
	}

	*discoveredApps = append(*discoveredApps, app)
}

func (service SnapshotService) inspectAndTrackApplication(
	ctx context.Context,
	seenRoots map[string]struct{},
	rootPath string,
) (model.LaravelApp, []model.Unknown, bool, bool) {
	if ctx.Err() != nil {
		return model.LaravelApp{}, nil, false, true
	}

	cleanRoot := filepath.Clean(strings.TrimSpace(rootPath))
	if cleanRoot == "." || cleanRoot == "" {
		return model.LaravelApp{}, nil, false, false
	}

	if _, alreadySeen := seenRoots[cleanRoot]; alreadySeen {
		return model.LaravelApp{}, nil, false, true
	}

	seenRoots[cleanRoot] = struct{}{}

	app, appUnknowns, isLaravelApp := service.inspectLaravelApplication(ctx, cleanRoot)
	if !isLaravelApp {
		return model.LaravelApp{}, appUnknowns, false, false
	}

	if app.ResolvedPath == "" || app.ResolvedPath == cleanRoot {
		return app, appUnknowns, true, false
	}

	seenRoots[app.ResolvedPath] = struct{}{}

	return app, appUnknowns, true, false
}
