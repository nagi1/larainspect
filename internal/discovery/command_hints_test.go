package discovery

import (
	"context"
	"errors"
	"io/fs"
	"strings"
	"testing"
	"time"

	"github.com/nagi1/larainspect/internal/model"
)

func TestAnyCommandAvailableReturnsTrueWhenOneCommandResolves(t *testing.T) {
	t.Parallel()

	service := newTestSnapshotService()
	service.lookPath = func(name string) (string, error) {
		if name == "php-fpm83" {
			return "/usr/bin/php-fpm83", nil
		}

		return "", fs.ErrNotExist
	}

	if !service.anyCommandAvailable([]string{"php-fpm", "php-fpm83"}) {
		t.Fatal("expected one resolved command to return true")
	}
	if service.anyCommandAvailable([]string{"php-fpm", "php-fpm85"}) {
		t.Fatal("expected no resolved commands to return false")
	}
}

func TestNormalizeCommandHintsTrimsDedupesAndCleansPaths(t *testing.T) {
	t.Parallel()

	got := normalizeCommandHints([]string{
		" ",
		"/www/server/php/85/sbin/../sbin/php-fpm",
		"/www/server/php/85/sbin/php-fpm",
		"/www/server/panel/vhost/nginx//*.conf",
		"php-fpm83",
		"php-fpm83",
	})

	want := []string{
		"/www/server/panel/vhost/nginx/*.conf",
		"/www/server/php/85/sbin/php-fpm",
		"php-fpm83",
	}
	if len(got) != len(want) {
		t.Fatalf("normalizeCommandHints() = %+v, want %+v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("normalizeCommandHints() = %+v, want %+v", got, want)
		}
	}
}

func TestCommandHintUnknownsCoverConfiguredAndFallbackPaths(t *testing.T) {
	t.Parallel()

	service := newTestSnapshotService()
	service.commandsEnabled = true
	service.lookPath = func(name string) (string, error) {
		return "", fs.ErrNotExist
	}

	configuredUnknowns := service.commandHintUnknowns(
		appDiscoveryCheckID,
		"Configured PHP-FPM binaries were not found",
		"PHP-FPM binaries were not found on PATH",
		"services.php_fpm.binaries",
		"PHP-FPM",
		[]string{"/www/server/php/83/sbin/php-fpm"},
		nil,
	)
	if len(configuredUnknowns) != 1 || configuredUnknowns[0].Title != "Configured PHP-FPM binaries were not found" {
		t.Fatalf("expected configured command unknown, got %+v", configuredUnknowns)
	}

	fallbackUnknowns := service.commandHintUnknowns(
		appDiscoveryCheckID,
		"Configured Nginx binary was not found",
		"Nginx binary was not found on PATH",
		"services.nginx.binary",
		"Nginx",
		[]string{"nginx"},
		[]string{"/etc/nginx/nginx.conf"},
	)
	if len(fallbackUnknowns) != 1 || fallbackUnknowns[0].Title != "Nginx binary was not found on PATH" {
		t.Fatalf("expected PATH fallback unknown, got %+v", fallbackUnknowns)
	}

	service.commandsEnabled = false
	if unknowns := service.commandHintUnknowns(appDiscoveryCheckID, "a", "b", "key", "label", []string{"nginx"}, []string{"/etc/nginx/nginx.conf"}); len(unknowns) != 0 {
		t.Fatalf("expected commands-disabled path to suppress hints, got %+v", unknowns)
	}
}

func TestCommandHintUnknownsSkipsWhenCommandResolvesOrNoEvidenceExists(t *testing.T) {
	t.Parallel()

	service := newTestSnapshotService()
	service.commandsEnabled = true
	service.lookPath = func(name string) (string, error) {
		if name == "nginx" {
			return "/usr/sbin/nginx", nil
		}

		return "", fs.ErrNotExist
	}

	if unknowns := service.commandHintUnknowns(appDiscoveryCheckID, "a", "b", "key", "label", []string{"nginx"}, []string{"/etc/nginx/nginx.conf"}); len(unknowns) != 0 {
		t.Fatalf("expected resolved command to suppress hints, got %+v", unknowns)
	}

	service.lookPath = func(name string) (string, error) { return "", fs.ErrNotExist }
	if unknowns := service.commandHintUnknowns(appDiscoveryCheckID, "a", "b", "key", "label", []string{"nginx"}, nil); len(unknowns) != 0 {
		t.Fatalf("expected no-path evidence to suppress PATH fallback hint, got %+v", unknowns)
	}
}

func TestCommandHintUnknownsSkipWhenAAPanelFallbackBinaryExists(t *testing.T) {
	t.Parallel()

	service := newTestSnapshotService()
	service.commandsEnabled = true
	service.lookPath = func(name string) (string, error) {
		return "", fs.ErrNotExist
	}
	service.statPath = func(path string) (fs.FileInfo, error) {
		switch path {
		case "/www/server/nginx/sbin/nginx", "/www/server/php/83/sbin/php-fpm", "/www/server/panel/pyenv/bin/supervisord":
			return fakeExecutableFileInfo{name: path}, nil
		default:
			return nil, fs.ErrNotExist
		}
	}

	if unknowns := service.commandHintUnknowns(appDiscoveryCheckID, "a", "b", "key", "label", []string{"nginx"}, []string{"/www/server/nginx/conf/nginx.conf"}); len(unknowns) != 0 {
		t.Fatalf("expected aaPanel nginx fallback to suppress hint, got %+v", unknowns)
	}
	if unknowns := service.commandHintUnknowns(appDiscoveryCheckID, "a", "b", "key", "label", []string{"php-fpm83"}, []string{"/www/server/php/83/etc/php-fpm.conf"}); len(unknowns) != 0 {
		t.Fatalf("expected aaPanel php-fpm fallback to suppress hint, got %+v", unknowns)
	}
	if unknowns := service.commandHintUnknowns(appDiscoveryCheckID, "a", "b", "key", "label", []string{"supervisord"}, []string{"/etc/supervisor/supervisord.conf"}); len(unknowns) != 0 {
		t.Fatalf("expected aaPanel supervisor fallback to suppress hint, got %+v", unknowns)
	}
}

func TestDiscoverNginxSitesFromCommandHandlesErrorBranches(t *testing.T) {
	t.Parallel()

	service := newTestSnapshotService()
	if _, _, ok := service.discoverNginxSitesFromCommand(context.Background()); ok {
		t.Fatal("expected commands-disabled service to skip command discovery")
	}

	service.commandsEnabled = true
	service.lookPath = func(name string) (string, error) {
		return "", fs.ErrNotExist
	}
	if _, unknowns, ok := service.discoverNginxSitesFromCommand(context.Background()); ok || len(unknowns) != 0 {
		t.Fatalf("expected missing default nginx binary to fall back silently, got ok=%v unknowns=%+v", ok, unknowns)
	}

	service.lookPath = func(name string) (string, error) {
		if name == "nginx" {
			return "/usr/sbin/nginx", nil
		}
		return "", fs.ErrNotExist
	}
	service.runCommand = func(_ context.Context, _ model.CommandRequest) (model.CommandResult, error) {
		return model.CommandResult{ExitCode: 1, Stderr: "test failed"}, nil
	}
	if _, unknowns, ok := service.discoverNginxSitesFromCommand(context.Background()); !ok || len(unknowns) != 1 || unknowns[0].Title != "Unable to inspect Nginx config" {
		t.Fatalf("expected command failure unknown, got ok=%v unknowns=%+v", ok, unknowns)
	}

	service.runCommand = func(_ context.Context, _ model.CommandRequest) (model.CommandResult, error) {
		return model.CommandResult{ExitCode: 0}, nil
	}
	if sites, unknowns, ok := service.discoverNginxSitesFromCommand(context.Background()); !ok || len(sites) != 0 || len(unknowns) != 0 {
		t.Fatalf("expected empty command output to return no sites and no unknowns, got ok=%v sites=%+v unknowns=%+v", ok, sites, unknowns)
	}

	service.runCommand = func(_ context.Context, _ model.CommandRequest) (model.CommandResult, error) {
		return model.CommandResult{ExitCode: 0, Stdout: "server {"}, nil
	}
	_, unknowns, ok := service.discoverNginxSitesFromCommand(context.Background())
	if !ok || len(unknowns) != 1 || unknowns[0].Error != model.ErrorKindParseFailure {
		t.Fatalf("expected parse-failure unknown, got ok=%v unknowns=%+v", ok, unknowns)
	}
	if !strings.Contains(unknowns[0].Evidence[0].Detail, "nginx -T") {
		t.Fatalf("expected command evidence, got %+v", unknowns[0])
	}
}

func TestDiscoverNginxSitesFromCommandUsesAAPanelFallbackBinary(t *testing.T) {
	t.Parallel()

	service := newTestSnapshotService()
	service.commandsEnabled = true
	service.lookPath = func(name string) (string, error) {
		return "", fs.ErrNotExist
	}
	service.statPath = func(path string) (fs.FileInfo, error) {
		if path == "/www/server/nginx/sbin/nginx" {
			return fakeExecutableFileInfo{name: path}, nil
		}
		return nil, fs.ErrNotExist
	}
	service.runCommand = func(_ context.Context, command model.CommandRequest) (model.CommandResult, error) {
		if command.Name != "/www/server/nginx/sbin/nginx" {
			t.Fatalf("expected aaPanel nginx binary, got %+v", command)
		}
		return model.CommandResult{ExitCode: 0, Stdout: "server { root /www/wwwroot/shop/current/public; }"}, nil
	}

	sites, unknowns, ok := service.discoverNginxSitesFromCommand(context.Background())
	if !ok || len(unknowns) != 0 || len(sites) != 1 {
		t.Fatalf("expected aaPanel nginx command discovery to succeed, got ok=%v sites=%+v unknowns=%+v", ok, sites, unknowns)
	}
}

type fakeExecutableFileInfo struct{ name string }

func (info fakeExecutableFileInfo) Name() string       { return info.name }
func (info fakeExecutableFileInfo) Size() int64        { return 0 }
func (info fakeExecutableFileInfo) Mode() fs.FileMode  { return 0o755 }
func (info fakeExecutableFileInfo) ModTime() time.Time { return time.Time{} }
func (info fakeExecutableFileInfo) IsDir() bool        { return false }
func (info fakeExecutableFileInfo) Sys() any           { return nil }

func TestReadConfigFilesFromPatternsSkipsMissingFilesAndReportsReadErrors(t *testing.T) {
	t.Parallel()

	service := newTestSnapshotService()
	service.globPaths = func(pattern string) ([]string, error) {
		return []string{"/etc/nginx/nginx.conf", "/etc/nginx/nginx.conf", "/etc/nginx/missing.conf"}, nil
	}
	service.readFile = func(path string) ([]byte, error) {
		switch path {
		case "/etc/nginx/nginx.conf":
			return []byte("server {}"), nil
		case "/etc/nginx/missing.conf":
			return nil, fs.ErrNotExist
		default:
			return nil, errors.New("unexpected path")
		}
	}

	files, unknowns := service.readConfigFilesFromPatterns(appDiscoveryCheckID, "Unable to read Nginx config", []string{"*.conf"})
	if len(unknowns) != 0 {
		t.Fatalf("expected missing files to be skipped without unknowns, got %+v", unknowns)
	}
	if len(files) != 1 || files[0].path != "/etc/nginx/nginx.conf" {
		t.Fatalf("expected deduped discovered files, got %+v", files)
	}
}
