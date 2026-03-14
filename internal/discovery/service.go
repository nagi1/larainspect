package discovery

import (
	"context"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/nagi1/larainspect/internal/fscache"
	"github.com/nagi1/larainspect/internal/model"
	"github.com/nagi1/larainspect/internal/rules"
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
	"php-fpm7.4",
	"php-fpm8.5",
	"php-fpm8.0",
	"php-fpm8.1",
	"php-fpm8.2",
	"php-fpm8.3",
	"php-fpm8.4",
	"php-fpm74",
	"php-fpm80",
	"php-fpm81",
	"php-fpm82",
	"php-fpm83",
	"php-fpm84",
	"php-fpm85",
	"ps",
	"pwd",
	"readlink",
	"ss",
	"stat",
	"supervisord",
	"systemctl",
	"tail",
	"uname",
	"ufw",
	"whoami",
}

var defaultPHPFPMCommands = []string{
	"php-fpm",
	"php-fpm8.5",
	"php-fpm8.4",
	"php-fpm8.3",
	"php-fpm8.2",
	"php-fpm8.1",
	"php-fpm8.0",
	"php-fpm7.4",
	"php-fpm85",
	"php-fpm84",
	"php-fpm83",
	"php-fpm82",
	"php-fpm81",
	"php-fpm80",
	"php-fpm74",
}

type Service interface {
	Discover(context.Context, model.ExecutionContext) (model.Snapshot, []model.Unknown, error)
}

var (
	_ Service = SnapshotService{}
	_ Service = NoopService{}
)

type SnapshotService struct {
	lookPath           func(string) (string, error)
	lookupUserName     func(string) (string, error)
	lookupGroupName    func(string) (string, error)
	readFile           func(string) ([]byte, error)
	statPath           func(string) (fs.FileInfo, error)
	lstatPath          func(string) (fs.FileInfo, error)
	globPaths          func(string) ([]string, error)
	walkDirectory      func(string, fs.WalkDirFunc) error
	resolveLinks       func(string) (string, error)
	runCommand         func(context.Context, model.CommandRequest) (model.CommandResult, error)
	commandsEnabled    bool
	nginxCommand       string
	phpFPMCommands     []string
	supervisorCommand  string
	nginxPatterns      []string
	phpFPMPatterns     []string
	mysqlPatterns      []string
	supervisorPatterns []string
	systemdPatterns    []string
	cronPatterns       []string
	sshPatterns        []string
	sshAccountPatterns []string
	sudoersPatterns    []string
	discoverNginx      bool
	discoverPHPFPM     bool
	discoverMySQL      bool
	discoverSupervisor bool
	discoverSystemd    bool
	discoverCron       bool
	discoverListeners  bool
	discoverSSH        bool
	discoverSudo       bool
	discoverFirewall   bool
	ruleEngine         rules.Engine
	ruleIssues         []model.Unknown
}

func NewService() SnapshotService {
	userLookup := func(uid string) (string, error) {
		resolvedUser, err := user.LookupId(uid)
		if err != nil {
			return "", err
		}
		return resolvedUser.Username, nil
	}
	groupLookup := func(gid string) (string, error) {
		resolvedGroup, err := user.LookupGroupId(gid)
		if err != nil {
			return "", err
		}
		return resolvedGroup.Name, nil
	}

	service := SnapshotService{
		lookPath:        exec.LookPath,
		lookupUserName:  userLookup,
		lookupGroupName: groupLookup,
		readFile:        os.ReadFile,
		statPath:        os.Stat,
		lstatPath:       os.Lstat,
		globPaths:       filepath.Glob,
		walkDirectory:   filepath.WalkDir,
		resolveLinks:    filepath.EvalSymlinks,
		runCommand: func(context.Context, model.CommandRequest) (model.CommandResult, error) {
			return model.CommandResult{}, fs.ErrPermission
		},
		nginxCommand:      "nginx",
		phpFPMCommands:    append([]string{}, defaultPHPFPMCommands...),
		supervisorCommand: "supervisord",
		nginxPatterns: []string{
			"/etc/nginx/nginx.conf",
			"/etc/nginx/conf.d/*.conf",
			"/etc/nginx/sites-enabled/*",
			"/usr/local/etc/nginx/nginx.conf",
			"/usr/local/etc/nginx/conf.d/*.conf",
			"/usr/local/etc/nginx/servers/*",
			"/www/server/nginx/conf/*.conf",
			"/www/server/nginx/conf/nginx.conf",
			"/www/server/nginx/conf/vhost/*.conf",
			"/www/server/nginx/src/conf/nginx.conf",
			"/www/server/panel/vhost/nginx/*.conf",
		},
		phpFPMPatterns: []string{
			"/etc/php/*/fpm/pool.d/*.conf",
			"/etc/php-fpm.d/*.conf",
			"/usr/local/etc/php-fpm.d/*.conf",
			"/www/server/php/*/etc/php-fpm.conf",
			"/www/server/php/*/etc/php-fpm.d/*.conf",
		},
		mysqlPatterns: []string{
			"/etc/mysql/my.cnf",
			"/etc/mysql/conf.d/*.cnf",
			"/etc/mysql/mysql.conf.d/*.cnf",
			"/etc/my.cnf",
			"/etc/my.cnf.d/*.cnf",
			"/www/server/mysql/etc/my.cnf",
			"/www/server/mysql/my.cnf",
		},
		supervisorPatterns: []string{
			"/etc/supervisor/*.conf",
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
		sshAccountPatterns: []string{
			"/root/.ssh",
			"/home/*/.ssh",
		},
		sudoersPatterns: []string{
			"/etc/sudoers",
			"/etc/sudoers.d/*",
		},
		discoverNginx:      true,
		discoverPHPFPM:     true,
		discoverMySQL:      true,
		discoverSupervisor: true,
		discoverSystemd:    true,
		discoverCron:       true,
		discoverListeners:  true,
		discoverSSH:        true,
		discoverSudo:       true,
		discoverFirewall:   true,
	}

	service.ruleEngine, service.ruleIssues = compileRuleEngine(model.RuleConfig{})

	return service
}

func NewServiceForAudit(config model.AuditConfig) SnapshotService {
	service := NewService()
	service.nginxPatterns = config.NormalizedNginxConfigPatterns()
	if configuredCommand := config.NormalizedNginxBinary(); configuredCommand != "" {
		service.nginxCommand = configuredCommand
	}
	if configuredCommands := config.NormalizedPHPFPMBinaries(); len(configuredCommands) > 0 {
		service.phpFPMCommands = configuredCommands
	}
	service.phpFPMPatterns = config.NormalizedPHPFPMPoolPatterns()
	service.mysqlPatterns = config.NormalizedMySQLConfigPatterns()
	if configuredCommand := config.NormalizedSupervisorBinary(); configuredCommand != "" {
		service.supervisorCommand = configuredCommand
	}
	service.supervisorPatterns = config.NormalizedSupervisorConfigPatterns()
	service.systemdPatterns = config.NormalizedSystemdUnitPatterns()
	service.discoverNginx = config.ShouldDiscoverNginx()
	service.discoverPHPFPM = config.ShouldDiscoverPHPFPM()
	service.discoverMySQL = config.ShouldDiscoverMySQL()
	service.discoverSupervisor = config.ShouldDiscoverSupervisor()
	service.discoverSystemd = config.ShouldDiscoverSystemd()
	service.ruleEngine, service.ruleIssues = compileRuleEngine(config.Rules)

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
	// Install a per-audit cache so repeated stat, read, and lookup calls within
	// one run are served from memory. The value receiver gives us an isolated copy.
	// We wrap the current function fields (which may have been overridden by tests)
	// rather than the raw fields, so test-injected behavior is preserved.
	cache := fscache.New()
	service.statPath = cache.WrapStat(service.statPath)
	service.lstatPath = cache.WrapLstat(service.lstatPath)
	service.readFile = cache.WrapReadFile(service.readFile)
	service.globPaths = cache.WrapGlob(service.globPaths)
	service.lookupUserName = cache.WrapLookup("u:", service.lookupUserName)
	service.lookupGroupName = cache.WrapLookup("g:", service.lookupGroupName)

	snapshot := model.Snapshot{
		Host:            execution.Host,
		Tools:           service.discoverToolAvailability(),
		Apps:            []model.LaravelApp{},
		RuleDefinitions: service.ruleDefinitionMap(),
	}
	if execution.Commands != nil {
		service.commandsEnabled = true
		service.runCommand = execution.Commands.Run
	} else if !service.commandsEnabled {
		service.commandsEnabled = false
	}
	unknowns := []model.Unknown{}
	unknowns = append(unknowns, service.ruleIssues...)

	if execution.Config.ShouldDiscoverApplications() {
		discoveredApps, discoveryUnknowns := service.discoverLaravelApplications(ctx, execution.Config)
		snapshot.Apps = discoveredApps
		unknowns = append(unknowns, discoveryUnknowns...)
	}

	service.appendServiceConfigs(ctx, execution.Config, &snapshot, &unknowns)

	return snapshot, unknowns, nil
}

func compileRuleEngine(config model.RuleConfig) (rules.Engine, []model.Unknown) {
	engine, issues := rules.New(config)
	unknowns := make([]model.Unknown, 0, len(issues))
	for _, issue := range issues {
		unknowns = append(unknowns, model.Unknown{
			ID:      "discovery.apps.rule_engine",
			CheckID: appDiscoveryCheckID,
			Title:   "Unable to fully load source rule engine",
			Reason:  issue.Error(),
			Error:   model.ErrorKindParseFailure,
			Evidence: []model.Evidence{
				{Label: "rule_id", Detail: strings.TrimSpace(issue.RuleID)},
				{Label: "path", Detail: strings.TrimSpace(issue.Path)},
			},
		})
	}

	return engine, compactUnknowns(unknowns)
}

func (service SnapshotService) ruleDefinitionMap() map[string]model.RuleDefinition {
	definitions := service.ruleEngine.Definitions()
	if len(definitions) == 0 {
		return nil
	}

	definitionMap := make(map[string]model.RuleDefinition, len(definitions))
	for _, definition := range definitions {
		definitionMap[definition.ID] = definition
	}
	return definitionMap
}

func compactUnknowns(unknowns []model.Unknown) []model.Unknown {
	compacted := make([]model.Unknown, 0, len(unknowns))
	seen := map[string]struct{}{}

	for _, unknown := range unknowns {
		key := unknown.Title + "\x00" + unknown.Reason
		if _, found := seen[key]; found {
			continue
		}
		seen[key] = struct{}{}

		evidence := []model.Evidence{}
		for _, item := range unknown.Evidence {
			if strings.TrimSpace(item.Detail) == "" {
				continue
			}
			evidence = append(evidence, item)
		}
		unknown.Evidence = evidence
		compacted = append(compacted, unknown)
	}

	return compacted
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
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Helper to launch a discovery goroutine that writes results under a lock.
	launchDiscover := func(enabled bool, discover func() ([]model.Unknown, func())) {
		if !enabled {
			return
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			u, assign := discover()
			mu.Lock()
			defer mu.Unlock()
			*unknowns = append(*unknowns, u...)
			assign()
		}()
	}

	launchDiscover(service.discoverNginx, func() ([]model.Unknown, func()) {
		items, u := service.discoverNginxSites(ctx)
		return u, func() { snapshot.NginxSites = items }
	})
	launchDiscover(service.discoverPHPFPM, func() ([]model.Unknown, func()) {
		items, u := service.discoverPHPFPMPools()
		return u, func() { snapshot.PHPFPMPools = items }
	})
	launchDiscover(service.discoverMySQL, func() ([]model.Unknown, func()) {
		items, u := service.discoverMySQLConfigs()
		return u, func() { snapshot.MySQLConfigs = items }
	})
	launchDiscover(service.discoverSystemd, func() ([]model.Unknown, func()) {
		items, u := service.discoverSystemdUnits()
		return u, func() { snapshot.SystemdUnits = items }
	})
	launchDiscover(service.discoverCron, func() ([]model.Unknown, func()) {
		items, u := service.discoverCronEntries()
		return u, func() { snapshot.CronEntries = items }
	})
	launchDiscover(service.discoverSupervisor, func() ([]model.Unknown, func()) {
		programs, httpServers, u := service.discoverSupervisorConfigs()
		return u, func() {
			snapshot.SupervisorPrograms = programs
			snapshot.SupervisorHTTPServers = httpServers
		}
	})

	hasAppContext := len(snapshot.Apps) > 0
	shouldDiscoverListeners := service.discoverListeners && (config.Scope == model.ScanScopeHost || (config.Scope == model.ScanScopeAuto && hasAppContext))
	launchDiscover(shouldDiscoverListeners, func() ([]model.Unknown, func()) {
		items, u := service.discoverListenersFromCommand(ctx)
		return u, func() { snapshot.Listeners = items }
	})

	isHostAudit := config.Scope == model.ScanScopeHost || (config.Scope == model.ScanScopeAuto && hasAppContext)
	launchDiscover(service.discoverSSH && isHostAudit, func() ([]model.Unknown, func()) {
		items, u := service.discoverSSHConfigs()
		return u, func() { snapshot.SSHConfigs = items }
	})
	launchDiscover(service.discoverSSH && isHostAudit, func() ([]model.Unknown, func()) {
		items, u := service.discoverSSHAccounts()
		return u, func() { snapshot.SSHAccounts = items }
	})
	launchDiscover(service.discoverSudo && isHostAudit, func() ([]model.Unknown, func()) {
		items, u := service.discoverSudoRules()
		return u, func() { snapshot.SudoRules = items }
	})
	launchDiscover(service.discoverFirewall && isHostAudit, func() ([]model.Unknown, func()) {
		items, u := service.discoverFirewallSummaries(ctx)
		return u, func() { snapshot.FirewallSummaries = items }
	})

	wg.Wait()
}

func (service SnapshotService) discoverLaravelApplications(ctx context.Context, config model.AuditConfig) ([]model.LaravelApp, []model.Unknown) {
	unknowns := []model.Unknown{}
	seenRoots := map[string]struct{}{}

	// Phase 1: Handle explicitly requested app path (must be first for dedup).
	var explicitApp *model.LaravelApp
	if explicitAppPath := strings.TrimSpace(config.AppPath); explicitAppPath != "" {
		cleanRoot := filepath.Clean(explicitAppPath)
		if cleanRoot != "." && cleanRoot != "" && ctx.Err() == nil {
			seenRoots[cleanRoot] = struct{}{}
			app, appUnknowns, isLaravelApp := service.inspectLaravelApplication(ctx, cleanRoot)
			unknowns = append(unknowns, appUnknowns...)
			if isLaravelApp {
				if app.ResolvedPath != "" && app.ResolvedPath != cleanRoot {
					seenRoots[app.ResolvedPath] = struct{}{}
				}
				explicitApp = &app
			} else if len(appUnknowns) == 0 {
				unknowns = append(unknowns, newRequestedAppUnknown(cleanRoot))
			}
		}
	}

	// Phase 2: Collect all unique candidate roots across scan roots.
	type candidateEntry struct {
		rootPath string
	}
	var candidates []candidateEntry
	for _, scanRoot := range config.EffectiveScanRoots() {
		candidateRoots, scanUnknowns := service.discoverCandidateRootsFromScanRoot(ctx, scanRoot)
		unknowns = append(unknowns, scanUnknowns...)

		for _, candidateRoot := range candidateRoots {
			cleanRoot := filepath.Clean(strings.TrimSpace(candidateRoot))
			if cleanRoot == "." || cleanRoot == "" {
				continue
			}
			if _, seen := seenRoots[cleanRoot]; seen {
				continue
			}
			seenRoots[cleanRoot] = struct{}{}
			candidates = append(candidates, candidateEntry{rootPath: cleanRoot})
		}
	}

	// Phase 3: Inspect candidates concurrently with bounded workers.
	type inspectResult struct {
		app      model.LaravelApp
		unknowns []model.Unknown
		isApp    bool
	}

	results := make([]inspectResult, len(candidates))
	if len(candidates) > 0 {
		var wg sync.WaitGroup
		sem := make(chan struct{}, 4) // bounded concurrency

		for i, candidate := range candidates {
			wg.Add(1)
			go func(idx int, rootPath string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				if ctx.Err() != nil {
					return
				}

				app, appUnknowns, isLaravelApp := service.inspectLaravelApplication(ctx, rootPath)
				results[idx] = inspectResult{
					app:      app,
					unknowns: appUnknowns,
					isApp:    isLaravelApp,
				}
			}(i, candidate.rootPath)
		}
		wg.Wait()
	}

	// Phase 4: Aggregate results deterministically (ordered by discovery index).
	discoveredApps := make([]model.LaravelApp, 0, len(results))
	for _, result := range results {
		unknowns = append(unknowns, result.unknowns...)
		if result.isApp {
			discoveredApps = append(discoveredApps, result.app)
		}
	}

	if explicitApp != nil {
		discoveredApps = append(discoveredApps, *explicitApp)
	}

	slices.SortFunc(discoveredApps, func(leftApp model.LaravelApp, rightApp model.LaravelApp) int {
		return strings.Compare(leftApp.RootPath, rightApp.RootPath)
	})

	return discoveredApps, unknowns
}
