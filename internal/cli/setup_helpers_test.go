package cli

import (
	"bytes"
	"io"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nagi1/larainspect/internal/model"
)

func TestSetupCommandHelpersCoverAliasesAndHelp(t *testing.T) {
	t.Parallel()

	app := NewAppWithInput(strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	if app.newInitCommand() == nil {
		t.Fatal("expected init command")
	}
	if app.newSetupCommand() == nil {
		t.Fatal("expected setup command")
	}

	for _, testCase := range []struct {
		input string
		want  configPreset
	}{
		{input: "", want: ""},
		{input: "default", want: presetVPS},
		{input: "forage", want: presetForge},
		{input: "do", want: presetDigitalOcean},
		{input: "aa_panel", want: presetAAPanel},
		{input: "c-panel", want: presetCPanel},
	} {
		got, err := resolveRequestedPreset(testCase.input)
		if err != nil {
			t.Fatalf("resolveRequestedPreset(%q) error = %v", testCase.input, err)
		}
		if got != testCase.want {
			t.Fatalf("resolveRequestedPreset(%q) = %q, want %q", testCase.input, got, testCase.want)
		}
	}

	if _, err := resolveRequestedPreset("unknown"); err == nil {
		t.Fatal("expected unsupported preset error")
	}

	inspector := newHostInspector()
	if inspector.getwd == nil || inspector.hostname == nil || inspector.stat == nil || inspector.glob == nil || inspector.readFile == nil || inspector.lookupOwner == nil {
		t.Fatal("expected host inspector functions to be initialized")
	}

	var initHelp bytes.Buffer
	printInitHelp(&initHelp)
	if initHelp.Len() == 0 {
		t.Fatal("expected init help output")
	}

	var setupHelp bytes.Buffer
	printSetupHelp(&setupHelp)
	if setupHelp.Len() == 0 {
		t.Fatal("expected setup help output")
	}

	var usage bytes.Buffer
	if exitCode := writeGeneratedConfigUsageError(&usage, os.ErrInvalid, printInitHelp); exitCode != int(model.ExitCodeUsageError) {
		t.Fatalf("unexpected usage exit code %d", exitCode)
	}
	if !strings.Contains(usage.String(), os.ErrInvalid.Error()) {
		t.Fatalf("expected usage output to include the error, got %q", usage.String())
	}
}

func TestSetupDiscoveryHelpers(t *testing.T) {
	t.Parallel()

	statPaths := map[string]fs.FileInfo{
		"/srv/app/artisan":                  fakeFileInfo{name: "artisan"},
		"/srv/app/composer.json":            fakeFileInfo{name: "composer.json"},
		"/srv/app/bootstrap/app.php":        fakeFileInfo{name: "app.php"},
		"/srv/app/public":                   fakeFileInfo{name: "public"},
		"/etc/nginx/conf.d/users":           fakeFileInfo{name: "users"},
		"/etc/nginx/conf.d/server-includes": fakeFileInfo{name: "server-includes"},
		"/bin/nginx":                        fakeExecutableInfo{name: "nginx"},
	}

	inspector := hostInspector{
		getwd: func() (string, error) { return "/srv/app/public", nil },
		stat: func(path string) (fs.FileInfo, error) {
			if info, ok := statPaths[path]; ok {
				return info, nil
			}
			return nil, fs.ErrNotExist
		},
		glob: func(pattern string) ([]string, error) {
			switch pattern {
			case "/home/forge/*/current":
				return []string{"/home/forge/site/current"}, nil
			case "/home/forge/*":
				return []string{"/home/forge/site"}, nil
			case "/var/www/*":
				return []string{"/var/www/example"}, nil
			case "/srv/www/*":
				return []string{"/srv/www/example"}, nil
			case "/www/wwwroot/*/current":
				return []string{"/www/wwwroot/shop/current"}, nil
			case "/www/wwwroot/*":
				return []string{"/www/wwwroot/shop"}, nil
			case "/home/*/*/current":
				return []string{"/home/alice/app/current"}, nil
			case "/home/*/laravel/*":
				return []string{"/home/alice/laravel/shop"}, nil
			case "/home/*/apps/*":
				return []string{"/home/alice/apps/api"}, nil
			default:
				return nil, nil
			}
		},
		readFile: func(path string) ([]byte, error) {
			if path == "/etc/os-release" {
				return []byte("ID=ubuntu\n"), nil
			}
			return nil, fs.ErrNotExist
		},
	}

	if got := detectOSFamily(inspector); got != "debian" {
		t.Fatalf("detectOSFamily() = %q, want debian", got)
	}
	if got := detectLaravelAppPath(inspector); got != "/srv/app" {
		t.Fatalf("detectLaravelAppPath() = %q", got)
	}
	if got := defaultGeneratedScope(inspector); got != model.ScanScopeApp {
		t.Fatalf("defaultGeneratedScope() = %q", got)
	}
	if !looksLikeLaravelApp(inspector, "/srv/app") {
		t.Fatal("expected Laravel app detection")
	}
	if got := resolveGeneratedConfigPath(""); got != defaultGeneratedConfigPath {
		t.Fatalf("resolveGeneratedConfigPath() = %q", got)
	}
	if got := firstExistingPath(inspector, "", "/bin/nginx", "/missing"); got != "/bin/nginx" {
		t.Fatalf("firstExistingPath() = %q", got)
	}
	if got := firstExistingPathOrDefault(inspector, " /fallback ", "/missing"); got != "/fallback" {
		t.Fatalf("firstExistingPathOrDefault() = %q", got)
	}
	if got := globMatches(inspector, "/var/www/*"); len(got) != 1 || got[0] != "/var/www/example" {
		t.Fatalf("globMatches() = %+v", got)
	}
	if !globHasMatch(inspector, "/var/www/*") {
		t.Fatal("expected globHasMatch() to be true")
	}
	if got := dedupeSorted([]string{" /b ", "/a", "/a"}); len(got) != 2 || got[0] != "/a" || got[1] != "/b" {
		t.Fatalf("dedupeSorted() = %+v", got)
	}
	if got := cpanelNginxConfigPatterns(inspector); len(got) != 3 {
		t.Fatalf("cpanelNginxConfigPatterns() = %+v", got)
	}
	if got := defaultGeneratedMySQLConfigPatterns(presetAAPanel, "debian"); len(got) != 3 {
		t.Fatalf("defaultGeneratedMySQLConfigPatterns() = %+v", got)
	}
	if got := defaultScanRoots(presetForge); len(got) != 1 || got[0] != "/home/forge" {
		t.Fatalf("defaultScanRoots() = %+v", got)
	}
	if got := candidateAppPathsForPreset(presetCPanel, inspector); len(got) != 3 {
		t.Fatalf("candidateAppPathsForPreset() = %+v", got)
	}
	if got := detectPlatformAppPath(presetForge, inspector); got != "" {
		t.Fatalf("detectPlatformAppPath() = %q, want empty when candidates are not Laravel apps", got)
	}
}

func TestIdentityHelpers(t *testing.T) {
	t.Parallel()

	pools := parseSetupPHPFPMPools("/etc/php-fpm.d/pools.conf", "[shop]\nuser = app\ngroup = app\n\n[ignored]\nuser = worker\ngroup = worker\n")
	if len(pools) != 2 {
		t.Fatalf("parseSetupPHPFPMPools() returned %d pools", len(pools))
	}
	if section, ok := iniSectionName("[shop]"); !ok || section != "shop" {
		t.Fatalf("iniSectionName() = %q %v", section, ok)
	}
	if values := collapseAmbiguousIdentityList([]string{"app", "worker"}); values != nil {
		t.Fatalf("collapseAmbiguousIdentityList() = %+v, want nil", values)
	}
	if values := collapseAmbiguousIdentityList([]string{"app", "app"}); len(values) != 1 || values[0] != "app" {
		t.Fatalf("collapseAmbiguousIdentityList() = %+v", values)
	}
	if !identitySliceContainsFold([]string{"WWW-Data"}, "www-data") {
		t.Fatal("expected case-insensitive identity match")
	}
	if got := setupAppIdentifierCandidates("/home/alice/apps/shop/current"); len(got) != 1 || got[0] != "shop" {
		t.Fatalf("setupAppIdentifierCandidates() = %+v", got)
	}
	if got := narrowSetupPHPFPMPoolsToApp(pools, "/srv/shop/current"); len(got) != 1 || got[0].Name != "shop" {
		t.Fatalf("narrowSetupPHPFPMPoolsToApp() = %+v", got)
	}
	if got := homeDirectoryUser("/home/alice/public_html"); got != "alice" {
		t.Fatalf("homeDirectoryUser() = %q", got)
	}

	inspector := hostInspector{
		stat: func(path string) (fs.FileInfo, error) {
			if path == "/etc/nginx/nginx.conf" {
				return fakeFileInfo{name: "nginx.conf"}, nil
			}
			return nil, fs.ErrNotExist
		},
		glob: func(pattern string) ([]string, error) {
			if pattern == "/etc/php/*/fpm/pool.d/*.conf" {
				return []string{"/etc/php/8.3/fpm/pool.d/shop.conf"}, nil
			}
			return nil, nil
		},
		readFile: func(path string) ([]byte, error) {
			switch path {
			case "/etc/nginx/nginx.conf":
				return []byte("user www-data www-data;\n"), nil
			case "/etc/php/8.3/fpm/pool.d/shop.conf":
				return []byte("[shop]\nuser = app\ngroup = app\n"), nil
			default:
				return nil, fs.ErrNotExist
			}
		},
		lookupOwner: func(path string) (string, error) { return "deployer", nil },
	}

	config := model.DefaultAuditConfig()
	config.AppPath = "/home/alice/apps/shop/current"
	config.Profile.OSFamily = "debian"
	config.Profile.Paths.PHPFPMPoolPatterns = []string{"/etc/php/*/fpm/pool.d/*.conf"}

	webUsers, webGroups := guessWebIdentities(presetVPS, inspector, config)
	if len(webUsers) != 1 || webUsers[0] != "www-data" || len(webGroups) != 1 || webGroups[0] != "www-data" {
		t.Fatalf("guessWebIdentities() = users=%+v groups=%+v", webUsers, webGroups)
	}

	runtimeUsers, runtimeGroups := guessRuntimeIdentities(inspector, config)
	if len(runtimeUsers) != 1 || runtimeUsers[0] != "app" || len(runtimeGroups) != 1 || runtimeGroups[0] != "app" {
		t.Fatalf("guessRuntimeIdentities() = users=%+v groups=%+v", runtimeUsers, runtimeGroups)
	}

	deployUsers := guessDeployUsers(inspector, config, presetIdentityDefaults{}, runtimeUsers, webUsers)
	if len(deployUsers) != 2 || deployUsers[0] != "alice" || deployUsers[1] != "deployer" {
		t.Fatalf("guessDeployUsers() = %+v", deployUsers)
	}

	if fallbackUsers, fallbackGroups := fallbackWebIdentities(presetVPS, model.AuditConfig{}); fallbackUsers != nil || fallbackGroups != nil {
		t.Fatalf("unexpected fallback web identities users=%+v groups=%+v", fallbackUsers, fallbackGroups)
	}
	if fallbackUsers, fallbackGroups := fallbackWebIdentities(presetVPS, model.AuditConfig{Profile: model.HostProfile{OSFamily: "rhel"}}); len(fallbackUsers) != 1 || fallbackUsers[0] != "nginx" || len(fallbackGroups) != 1 || fallbackGroups[0] != "nginx" {
		t.Fatalf("unexpected rhel fallback web identities users=%+v groups=%+v", fallbackUsers, fallbackGroups)
	}
}

func TestLookupPathOwnerName(t *testing.T) {
	t.Parallel()

	currentUser, err := user.Current()
	if err != nil {
		t.Fatalf("Current() error = %v", err)
	}

	filePath := filepath.Join(t.TempDir(), "owner.txt")
	if err := os.WriteFile(filePath, []byte("owner"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	ownerName, err := lookupPathOwnerName(filePath)
	if err != nil {
		t.Fatalf("lookupPathOwnerName() error = %v", err)
	}
	if ownerName != currentUser.Username {
		t.Fatalf("lookupPathOwnerName() = %q, want %q", ownerName, currentUser.Username)
	}
}

func TestGeneratedCommandPresetValidationAndDetection(t *testing.T) {
	t.Parallel()

	for _, runCommand := range []func(io.Reader, io.Writer, io.Writer, generatedConfigOptions, hostInspector) int{
		func(_ io.Reader, stdout io.Writer, stderr io.Writer, options generatedConfigOptions, inspector hostInspector) int {
			return runInitCommandWithInspector(stdout, stderr, options, inspector)
		},
		runSetupCommandWithInspector,
	} {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		exitCode := runCommand(strings.NewReader(""), &stdout, &stderr, generatedConfigOptions{preset: "invalid"}, hostInspector{})
		if exitCode != int(model.ExitCodeUsageError) {
			t.Fatalf("unexpected exit code %d", exitCode)
		}
		if !strings.Contains(stderr.String(), "unsupported preset") {
			t.Fatalf("expected preset error, got %q", stderr.String())
		}
	}

	for _, testCase := range []struct {
		name string
		path string
		want configPreset
	}{
		{name: "aaPanel", path: "/www/server/panel", want: presetAAPanel},
		{name: "cPanel", path: "/usr/local/cpanel", want: presetCPanel},
		{name: "Forge", path: "/home/forge", want: presetForge},
		{name: "DigitalOcean", path: "/etc/digitalocean", want: presetDigitalOcean},
	} {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			guess, ok := detectHostingPreset(hostInspector{
				stat: func(path string) (fs.FileInfo, error) {
					if path == testCase.path {
						return fakeFileInfo{name: filepath.Base(path)}, nil
					}
					return nil, fs.ErrNotExist
				},
			})
			if !ok || guess.preset != testCase.want {
				t.Fatalf("detectHostingPreset() = %+v, %v", guess, ok)
			}
		})
	}

	if _, ok := detectHostingPreset(hostInspector{stat: func(path string) (fs.FileInfo, error) { return nil, fs.ErrNotExist }}); ok {
		t.Fatal("expected no preset detection")
	}
}

func TestDetectOSFamilyFallbacks(t *testing.T) {
	t.Parallel()

	if got := detectOSFamily(hostInspector{readFile: func(path string) ([]byte, error) { return []byte("ID=rocky\n"), nil }}); got != "rhel" {
		t.Fatalf("detectOSFamily() = %q, want rhel", got)
	}
	if got := detectOSFamily(hostInspector{readFile: func(path string) ([]byte, error) { return nil, fs.ErrNotExist }}); got != "auto" {
		t.Fatalf("detectOSFamily() = %q, want auto", got)
	}
	if got := detectOSFamily(hostInspector{}); got != "auto" {
		t.Fatalf("detectOSFamily() = %q, want auto", got)
	}
}
