package cli

import (
	"bytes"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDetectHostingPresetRecognizesAAPanel(t *testing.T) {
	t.Parallel()

	inspector := hostInspector{
		stat: func(path string) (fs.FileInfo, error) {
			if path == "/www/server/panel" {
				return fakeFileInfo{name: filepath.Base(path)}, nil
			}
			return nil, fs.ErrNotExist
		},
	}

	guess, ok := detectHostingPreset(inspector)
	if !ok {
		t.Fatal("expected aaPanel detection")
	}
	if guess.preset != presetAAPanel {
		t.Fatalf("expected aaPanel preset, got %q", guess.preset)
	}
}

func TestBuildGeneratedConfigForAAPanelAddsPanelBinaries(t *testing.T) {
	t.Parallel()

	inspector := hostInspector{
		hostname: func() (string, error) { return "panel-host", nil },
		glob: func(pattern string) ([]string, error) {
			if pattern == "/www/server/php/*/sbin/php-fpm" {
				return []string{"/www/server/php/85/sbin/php-fpm", "/www/server/php/83/sbin/php-fpm"}, nil
			}
			return nil, nil
		},
	}

	config := buildGeneratedConfig(presetAAPanel, inspector, generatedAnswers{})
	if config.Profile.Commands.NginxBinary != "/www/server/nginx/sbin/nginx" {
		t.Fatalf("unexpected nginx binary %q", config.Profile.Commands.NginxBinary)
	}
	if len(config.Profile.Commands.PHPFPMBinaries) != 2 {
		t.Fatalf("expected php-fpm binaries, got %+v", config.Profile.Commands.PHPFPMBinaries)
	}
	if config.Profile.Name != "panel-host" {
		t.Fatalf("expected hostname, got %q", config.Profile.Name)
	}
}

func TestBuildGeneratedConfigForCPanelAddsNginxPatternsWhenPresent(t *testing.T) {
	t.Parallel()

	inspector := hostInspector{
		stat: func(path string) (fs.FileInfo, error) {
			switch path {
			case "/etc/nginx/conf.d/users", "/etc/nginx/conf.d/server-includes", "/etc/nginx/conf.d":
				return fakeFileInfo{name: filepath.Base(path)}, nil
			default:
				return nil, fs.ErrNotExist
			}
		},
	}

	config := buildGeneratedConfig(presetCPanel, inspector, generatedAnswers{})
	if !config.ShouldDiscoverNginx() {
		t.Fatal("expected cPanel preset to enable nginx discovery when nginx config directories exist")
	}
	if config.Profile.Paths.UseDefaultPatterns {
		t.Fatal("expected cPanel preset to replace default discovery patterns")
	}
	if len(config.Profile.Paths.NginxConfigPatterns) == 0 {
		t.Fatalf("expected cPanel nginx patterns, got %+v", config.Profile.Paths.NginxConfigPatterns)
	}
	if config.ShouldDiscoverSupervisor() {
		t.Fatal("expected cPanel preset to disable supervisor discovery")
	}
}

func TestBuildGeneratedConfigForDigitalOceanFindsDefaultAppPath(t *testing.T) {
	t.Parallel()

	inspector := hostInspector{
		stat: func(path string) (fs.FileInfo, error) {
			switch path {
			case "/var/www/laravel", "/var/www/laravel/artisan", "/var/www/laravel/composer.json", "/var/www/laravel/bootstrap/app.php":
				return fakeFileInfo{name: filepath.Base(path)}, nil
			default:
				return nil, fs.ErrNotExist
			}
		},
	}

	config := buildGeneratedConfig(presetDigitalOcean, inspector, generatedAnswers{})
	if config.AppPath != "/var/www/laravel" {
		t.Fatalf("expected DigitalOcean default app path, got %q", config.AppPath)
	}
	if config.Scope != model.ScanScopeApp {
		t.Fatalf("expected app scope when a default Laravel root is found, got %q", config.Scope)
	}
}

func TestRunInitCommandWritesConfig(t *testing.T) {
	t.Parallel()

	outputPath := filepath.Join(t.TempDir(), "larainspect.yaml")
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	inspector := hostInspector{
		getwd:    func() (string, error) { return "/tmp", nil },
		hostname: func() (string, error) { return "example-host", nil },
		stat:     func(path string) (fs.FileInfo, error) { return nil, fs.ErrNotExist },
		readFile: func(path string) ([]byte, error) { return []byte("ID=ubuntu\n"), nil },
	}

	exitCode := runInitCommandWithInspector(&stdout, &stderr, generatedConfigOptions{path: outputPath}, inspector)
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d stderr=%q", exitCode, stderr.String())
	}

	contents, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if !strings.Contains(string(contents), "version: 1") || !strings.Contains(string(contents), "name: example-host") {
		t.Fatalf("unexpected generated config %q", string(contents))
	}
	if !strings.Contains(stdout.String(), "Wrote") {
		t.Fatalf("expected success output, got %q", stdout.String())
	}
}

func TestRunSetupCommandPromptsWhenDetectionFails(t *testing.T) {
	t.Parallel()

	outputPath := filepath.Join(t.TempDir(), "larainspect.yaml")
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	inspector := hostInspector{
		getwd:    func() (string, error) { return "/tmp", nil },
		hostname: func() (string, error) { return "wizard-host", nil },
		stat:     func(path string) (fs.FileInfo, error) { return nil, fs.ErrNotExist },
		readFile: func(path string) ([]byte, error) { return []byte("ID=ubuntu\n"), nil },
	}

	input := strings.NewReader("aapanel\n\napp\n/www/wwwroot/shop\n")
	exitCode := runSetupCommandWithInspector(input, &stdout, &stderr, generatedConfigOptions{path: outputPath}, inspector)
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d stderr=%q", exitCode, stderr.String())
	}

	contents, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if !strings.Contains(string(contents), "/www/server/nginx/sbin/nginx") {
		t.Fatalf("expected aaPanel nginx binary in generated config, got %q", string(contents))
	}
	if !strings.Contains(string(contents), "scope: app") || !strings.Contains(string(contents), "app_path: /www/wwwroot/shop") {
		t.Fatalf("expected prompted app scope in generated config, got %q", string(contents))
	}
	if !strings.Contains(stderr.String(), "Could not confidently detect the hosting preset") {
		t.Fatalf("expected setup prompt guidance, got %q", stderr.String())
	}
}

func TestAppRootHelpListsInitAndSetup(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := NewApp(&stdout, &stderr).Run(context.Background(), nil)
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}
	if !strings.Contains(stdout.String(), "larainspect init") || !strings.Contains(stdout.String(), "larainspect setup") {
		t.Fatalf("expected init and setup in root help, got %q", stdout.String())
	}
}

type fakeFileInfo struct{ name string }

func (info fakeFileInfo) Name() string       { return info.name }
func (info fakeFileInfo) Size() int64        { return 0 }
func (info fakeFileInfo) Mode() fs.FileMode  { return 0o755 }
func (info fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (info fakeFileInfo) IsDir() bool        { return true }
func (info fakeFileInfo) Sys() any           { return nil }
