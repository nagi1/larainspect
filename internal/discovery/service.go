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
	"find",
	"hostname",
	"ip",
	"ls",
	"nginx",
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
	"whoami",
}

type Service interface {
	Discover(context.Context, model.ExecutionContext) (model.Snapshot, []model.Unknown, error)
}

type SnapshotService struct {
	lookPath       func(string) (string, error)
	readFile       func(string) ([]byte, error)
	statPath       func(string) (fs.FileInfo, error)
	lstatPath      func(string) (fs.FileInfo, error)
	globPaths      func(string) ([]string, error)
	walkDirectory  func(string, fs.WalkDirFunc) error
	resolveLinks   func(string) (string, error)
	nginxPatterns  []string
	phpFPMPatterns []string
	discoverNginx  bool
	discoverPHPFPM bool
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
		discoverNginx:  true,
		discoverPHPFPM: true,
	}
}

func NewServiceForAudit(config model.AuditConfig) SnapshotService {
	service := NewService()
	service.nginxPatterns = config.NormalizedNginxConfigPatterns()
	service.phpFPMPatterns = config.NormalizedPHPFPMPoolPatterns()
	service.discoverNginx = config.ShouldDiscoverNginx()
	service.discoverPHPFPM = config.ShouldDiscoverPHPFPM()

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
	unknowns := []model.Unknown{}

	if execution.Config.ShouldDiscoverApplications() {
		discoveredApps, discoveryUnknowns := service.discoverLaravelApplications(ctx, execution.Config)
		snapshot.Apps = discoveredApps
		unknowns = append(unknowns, discoveryUnknowns...)
	}

	service.appendServiceConfigs(&snapshot, &unknowns)

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

func (service SnapshotService) appendServiceConfigs(snapshot *model.Snapshot, unknowns *[]model.Unknown) {
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

	snapshot.NginxSites = nginxSites
	snapshot.PHPFPMPools = phpFPMPools
	*unknowns = append(*unknowns, nginxUnknowns...)
	*unknowns = append(*unknowns, phpFPMUnknowns...)
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
