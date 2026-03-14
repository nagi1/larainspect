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
}

func TestProfileHelpersAllowReplacingDefaultPatterns(t *testing.T) {
	t.Parallel()

	config := model.DefaultAuditConfig()
	config.Profile.Paths.UseDefaultPatterns = false
	config.Profile.Paths.PHPFPMPoolPatterns = []string{"/srv/php/pools/*.conf"}

	patterns := config.NormalizedPHPFPMPoolPatterns()
	if len(patterns) != 1 || patterns[0] != "/srv/php/pools/*.conf" {
		t.Fatalf("NormalizedPHPFPMPoolPatterns() = %+v", patterns)
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
