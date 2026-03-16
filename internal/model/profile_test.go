package model_test

import (
	"testing"

	"github.com/nagi1/larainspect/internal/model"
)

func TestDefaultAuditConfigUsesSafeProfileDefaults(t *testing.T) {
	t.Parallel()

	config := model.DefaultAuditConfig()
	if config.Profile.Paths.UseDefaultPatterns != true {
		t.Fatal("expected default profile to use built-in patterns")
	}
	if !config.ShouldDiscoverNginx() || !config.ShouldDiscoverPHPFPM() || !config.ShouldDiscoverSupervisor() || !config.ShouldDiscoverSystemd() {
		t.Fatalf("expected default service discovery switches, got %+v", config.Profile.Switches)
	}
	if !config.ShouldDiscoverMySQL() {
		t.Fatalf("expected mysql discovery to be enabled by default, got %+v", config.Profile.Switches)
	}
}

func TestProfileHelpersNormalizeOSFamilyAndPatterns(t *testing.T) {
	t.Parallel()

	config := model.DefaultAuditConfig()
	config.Profile.OSFamily = "fedora"
	config.Profile.Paths.AppScanRoots = []string{" /srv/www ", "/opt/apps", "/srv/www"}
	config.Profile.Paths.NginxConfigPatterns = []string{"/custom/nginx/*.conf"}

	if got := config.NormalizedOSFamily(); got != "rhel" {
		t.Fatalf("NormalizedOSFamily() = %q, want rhel", got)
	}

	scanRoots := config.EffectiveScanRoots()
	if len(scanRoots) != 2 || scanRoots[0] != "/opt/apps" || scanRoots[1] != "/srv/www" {
		t.Fatalf("EffectiveScanRoots() = %+v", scanRoots)
	}

	nginxPatterns := config.NormalizedNginxConfigPatterns()
	if len(nginxPatterns) < 2 {
		t.Fatalf("expected default and custom nginx patterns, got %+v", nginxPatterns)
	}

	phpPatterns := config.NormalizedPHPFPMPoolPatterns()
	for _, pattern := range phpPatterns {
		if pattern == "/etc/php/*/fpm/pool.d/*.conf" {
			t.Fatalf("did not expect debian php-fpm pattern for fedora/rhel profile: %+v", phpPatterns)
		}
	}

	foundAAPanelPHPPattern := false
	for _, pattern := range phpPatterns {
		if pattern == "/www/server/php/*/etc/php-fpm.conf" {
			foundAAPanelPHPPattern = true
			break
		}
	}
	if !foundAAPanelPHPPattern {
		t.Fatalf("expected aaPanel php-fpm main config pattern, got %+v", phpPatterns)
	}

	phpINIPatterns := config.NormalizedPHPINIConfigPatterns()
	if len(phpINIPatterns) == 0 {
		t.Fatal("expected php.ini patterns to be available")
	}
	foundPHPRuntimeINI := false
	for _, pattern := range phpINIPatterns {
		if pattern == "/etc/php.ini" {
			foundPHPRuntimeINI = true
			break
		}
	}
	if !foundPHPRuntimeINI {
		t.Fatalf("expected rhel-family php.ini pattern, got %+v", phpINIPatterns)
	}

	mysqlPatterns := config.NormalizedMySQLConfigPatterns()
	foundMySQLPattern := false
	for _, pattern := range mysqlPatterns {
		if pattern == "/etc/my.cnf" {
			foundMySQLPattern = true
			break
		}
	}
	if !foundMySQLPattern {
		t.Fatalf("expected mysql config pattern, got %+v", mysqlPatterns)
	}
}

func TestProfileHelpersAllowReplacingDefaultPatterns(t *testing.T) {
	t.Parallel()

	config := model.DefaultAuditConfig()
	config.Profile.Paths.UseDefaultPatterns = false
	config.Profile.Paths.PHPFPMPoolPatterns = []string{"/srv/php/pools/*.conf"}
	config.Profile.Paths.PHPINIConfigPatterns = []string{"/srv/php/php.ini"}

	patterns := config.NormalizedPHPFPMPoolPatterns()
	if len(patterns) != 1 || patterns[0] != "/srv/php/pools/*.conf" {
		t.Fatalf("NormalizedPHPFPMPoolPatterns() = %+v", patterns)
	}
	phpINIPatterns := config.NormalizedPHPINIConfigPatterns()
	if len(phpINIPatterns) != 1 || phpINIPatterns[0] != "/srv/php/php.ini" {
		t.Fatalf("NormalizedPHPINIConfigPatterns() = %+v", phpINIPatterns)
	}
}

func TestProfileHelpersNormalizeProfileNameAndServicePatterns(t *testing.T) {
	t.Parallel()

	config := model.DefaultAuditConfig()
	config.Profile.Name = "  fedora edge  "
	config.Profile.OSFamily = "rocky"

	if got := config.NormalizedProfileName(); got != "fedora edge" {
		t.Fatalf("NormalizedProfileName() = %q, want %q", got, "fedora edge")
	}

	supervisorPatterns := config.NormalizedSupervisorConfigPatterns()
	if len(supervisorPatterns) == 0 {
		t.Fatal("expected built-in supervisor patterns")
	}

	systemdPatterns := config.NormalizedSystemdUnitPatterns()
	if len(systemdPatterns) == 0 {
		t.Fatal("expected built-in systemd patterns")
	}

	foundRHELSupervisorPath := false
	foundAAPanelNginxPath := false
	for _, pattern := range supervisorPatterns {
		if pattern == "/etc/supervisord.d/*.ini" {
			foundRHELSupervisorPath = true
		}
	}
	for _, pattern := range config.NormalizedNginxConfigPatterns() {
		if pattern == "/www/server/nginx/conf/*.conf" {
			foundAAPanelNginxPath = true
		}
		if pattern == "/www/server/panel/vhost/nginx/*.conf" {
			foundAAPanelNginxPath = true
			break
		}
	}

	if !foundRHELSupervisorPath {
		t.Fatalf("expected rhel-family supervisor pattern, got %+v", supervisorPatterns)
	}
	if !foundAAPanelNginxPath {
		t.Fatalf("expected aaPanel nginx vhost pattern, got %+v", config.NormalizedNginxConfigPatterns())
	}

	foundGenericSupervisorPath := false
	for _, pattern := range model.DefaultAuditConfig().NormalizedSupervisorConfigPatterns() {
		if pattern == "/etc/supervisor/*.conf" {
			foundGenericSupervisorPath = true
			break
		}
	}
	if !foundGenericSupervisorPath {
		t.Fatalf("expected generic supervisor directory pattern, got %+v", model.DefaultAuditConfig().NormalizedSupervisorConfigPatterns())
	}
}

func TestProfileHelpersNormalizeConfiguredCommandPaths(t *testing.T) {
	t.Parallel()

	config := model.DefaultAuditConfig()
	config.Profile.Commands.NginxBinary = " /www/server/nginx/sbin/nginx "
	config.Profile.Commands.PHPFPMBinaries = []string{
		" /www/server/php/83/sbin/php-fpm ",
		"/www/server/php/85/sbin/../sbin/php-fpm",
		"/www/server/php/83/sbin/php-fpm",
	}
	config.Profile.Commands.SupervisorBinary = " /www/server/panel/pyenv/bin/supervisord "

	if got := config.NormalizedNginxBinary(); got != "/www/server/nginx/sbin/nginx" {
		t.Fatalf("NormalizedNginxBinary() = %q", got)
	}

	phpFPMBinaries := config.NormalizedPHPFPMBinaries()
	if len(phpFPMBinaries) != 2 || phpFPMBinaries[0] != "/www/server/php/83/sbin/php-fpm" || phpFPMBinaries[1] != "/www/server/php/85/sbin/php-fpm" {
		t.Fatalf("NormalizedPHPFPMBinaries() = %+v", phpFPMBinaries)
	}

	if got := config.NormalizedSupervisorBinary(); got != "/www/server/panel/pyenv/bin/supervisord" {
		t.Fatalf("NormalizedSupervisorBinary() = %q", got)
	}
}

func TestProfileHelpersNormalizeConfiguredIdentities(t *testing.T) {
	t.Parallel()

	config := model.DefaultAuditConfig()
	config.Identities = model.IdentityConfig{
		DeployUsers:   []string{" Forge ", "forge", "deploy"},
		RuntimeUsers:  []string{"www", "WWW", "php"},
		RuntimeGroups: []string{"www", " www ", "php"},
		WebUsers:      []string{"www-data", "WWW-DATA"},
		WebGroups:     []string{"www-data", " www-data "},
	}

	if got := config.NormalizedDeployUsers(); len(got) != 2 || got[0] != "deploy" || got[1] != "Forge" {
		t.Fatalf("NormalizedDeployUsers() = %+v", got)
	}
	if got := config.NormalizedRuntimeUsers(); len(got) != 2 || got[0] != "php" || got[1] != "www" {
		t.Fatalf("NormalizedRuntimeUsers() = %+v", got)
	}
	if got := config.NormalizedRuntimeGroups(); len(got) != 2 || got[0] != "php" || got[1] != "www" {
		t.Fatalf("NormalizedRuntimeGroups() = %+v", got)
	}
	if got := config.NormalizedWebUsers(); len(got) != 1 || got[0] != "www-data" {
		t.Fatalf("NormalizedWebUsers() = %+v", got)
	}
	if got := config.NormalizedWebGroups(); len(got) != 1 || got[0] != "www-data" {
		t.Fatalf("NormalizedWebGroups() = %+v", got)
	}
}
