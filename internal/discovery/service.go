package discovery

import (
	"context"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/nagi/larainspect/internal/model"
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
	lookPath      func(string) (string, error)
	readFile      func(string) ([]byte, error)
	statPath      func(string) (fs.FileInfo, error)
	walkDirectory func(string, fs.WalkDirFunc) error
	resolveLinks  func(string) (string, error)
}

func NewService() SnapshotService {
	return SnapshotService{
		lookPath:      exec.LookPath,
		readFile:      os.ReadFile,
		statPath:      os.Stat,
		walkDirectory: filepath.WalkDir,
		resolveLinks:  filepath.EvalSymlinks,
	}
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

	if !execution.Config.ShouldDiscoverApplications() {
		return snapshot, unknowns, nil
	}

	discoveredApps, discoveryUnknowns := service.discoverLaravelApplications(ctx, execution.Config)
	snapshot.Apps = discoveredApps
	unknowns = append(unknowns, discoveryUnknowns...)

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

func (service SnapshotService) discoverLaravelApplications(ctx context.Context, config model.AuditConfig) ([]model.LaravelApp, []model.Unknown) {
	discoveredApps := []model.LaravelApp{}
	unknowns := []model.Unknown{}
	seenRoots := map[string]struct{}{}

	if explicitAppPath := strings.TrimSpace(config.AppPath); explicitAppPath != "" {
		service.appendRequestedApplication(ctx, &discoveredApps, &unknowns, seenRoots, explicitAppPath)
	}

	for _, scanRoot := range config.NormalizedScanRoots() {
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

	app, appUnknowns, isLaravelApp := service.inspectLaravelApplication(cleanRoot)
	if !isLaravelApp {
		return model.LaravelApp{}, appUnknowns, false, false
	}

	if app.ResolvedPath == "" || app.ResolvedPath == cleanRoot {
		return app, appUnknowns, true, false
	}

	seenRoots[app.ResolvedPath] = struct{}{}

	return app, appUnknowns, true, false
}
