package discovery

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDiscoverPHPFPMPoolsReportsConfiguredMissingBinaries(t *testing.T) {
	t.Parallel()

	configRoot := t.TempDir()
	phpFPMConfigPath := filepath.Join(configRoot, "php-fpm", "shop.conf")
	if err := os.MkdirAll(filepath.Dir(phpFPMConfigPath), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	writeTestFile(t, phpFPMConfigPath, "[shop]\nuser = www-data\nlisten = /run/php/shop.sock\n")

	service := newTestSnapshotService()
	service.commandsEnabled = true
	service.phpFPMPatterns = []string{phpFPMConfigPath}
	service.phpFPMCommands = []string{"/www/server/php/83/sbin/php-fpm", "/www/server/php/85/sbin/php-fpm"}
	service.lookPath = func(name string) (string, error) {
		return "", os.ErrNotExist
	}

	_, unknowns := service.discoverPHPFPMPools()
	if len(unknowns) != 1 {
		t.Fatalf("expected 1 unknown, got %+v", unknowns)
	}
	if unknowns[0].Title != "Configured PHP-FPM binaries were not found" {
		t.Fatalf("unexpected unknown %+v", unknowns[0])
	}
	if !strings.Contains(unknowns[0].Reason, "services.php_fpm.binaries") {
		t.Fatalf("expected config hint, got %+v", unknowns[0])
	}
}

func TestDiscoverSupervisorConfigsReportsBinaryFallbackHint(t *testing.T) {
	t.Parallel()

	configRoot := t.TempDir()
	supervisorConfigPath := filepath.Join(configRoot, "supervisor", "laravel.conf")
	if err := os.MkdirAll(filepath.Dir(supervisorConfigPath), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	writeTestFile(t, supervisorConfigPath, "[program:worker]\ncommand=/usr/bin/php /var/www/shop/current/artisan queue:work\n")

	service := newTestSnapshotService()
	service.commandsEnabled = true
	service.supervisorPatterns = []string{supervisorConfigPath}
	service.supervisorCommand = "supervisord"
	service.lookPath = func(name string) (string, error) {
		return "", os.ErrNotExist
	}

	_, _, unknowns := service.discoverSupervisorConfigs()
	if len(unknowns) != 1 {
		t.Fatalf("expected 1 unknown, got %+v", unknowns)
	}
	if unknowns[0].Title != "Supervisor binary was not found on PATH" {
		t.Fatalf("unexpected unknown %+v", unknowns[0])
	}
	if !strings.Contains(unknowns[0].Reason, "services.supervisor.binary") {
		t.Fatalf("expected config hint, got %+v", unknowns[0])
	}
}
