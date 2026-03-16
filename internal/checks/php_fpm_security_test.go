package checks_test

import (
	"context"
	"testing"

	"github.com/nagi1/larainspect/internal/checks"
	"github.com/nagi1/larainspect/internal/model"
)

func TestPHPFPMSecurityCheckReportsLoopbackTCPPreferenceGap(t *testing.T) {
	t.Parallel()

	result, err := checks.PHPFPMSecurityCheck{}.Run(context.Background(), model.ExecutionContext{}, model.Snapshot{
		PHPFPMPools: []model.PHPFPMPool{{
			ConfigPath: "/etc/php/8.3/fpm/pool.d/shop.conf",
			Name:       "shop",
			User:       "www-data",
			Listen:     "127.0.0.1:9000",
		}},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if len(result.Findings) != 1 || result.Findings[0].Title != "PHP-FPM uses a local TCP port instead of a Unix socket" {
		t.Fatalf("expected loopback TCP finding, got %+v", result.Findings)
	}
}

func TestPHPFPMSecurityCheckReportsMissingSocketACL(t *testing.T) {
	t.Parallel()

	result, err := checks.PHPFPMSecurityCheck{}.Run(context.Background(), model.ExecutionContext{}, model.Snapshot{
		PHPFPMPools: []model.PHPFPMPool{{
			ConfigPath: "/etc/php/8.3/fpm/pool.d/shop.conf",
			Name:       "shop",
			User:       "www-data",
			Listen:     "/run/php/shop.sock",
			ListenMode: "0660",
		}},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if len(result.Findings) != 1 || result.Findings[0].Title != "PHP-FPM socket owner and group are not set explicitly" {
		t.Fatalf("expected missing socket ACL finding, got %+v", result.Findings)
	}
}

func TestPHPFPMSecurityCheckReportsSocketModeBeyond0660(t *testing.T) {
	t.Parallel()

	result, err := checks.PHPFPMSecurityCheck{}.Run(context.Background(), model.ExecutionContext{}, model.Snapshot{
		PHPFPMPools: []model.PHPFPMPool{{
			ConfigPath:  "/etc/php/8.3/fpm/pool.d/shop.conf",
			Name:        "shop",
			User:        "app-shop",
			Group:       "app-shop",
			Listen:      "/run/php/shop.sock",
			ListenOwner: "www-data",
			ListenGroup: "www-data",
			ListenMode:  "0664",
		}},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if len(result.Findings) != 1 || result.Findings[0].Title != "PHP-FPM socket is accessible to more users than needed" {
		t.Fatalf("expected broad socket mode finding, got %+v", result.Findings)
	}
}

func TestPHPFPMSecurityCheckReportsCollapsedSocketBoundary(t *testing.T) {
	t.Parallel()

	result, err := checks.PHPFPMSecurityCheck{}.Run(context.Background(), model.ExecutionContext{}, model.Snapshot{
		PHPFPMPools: []model.PHPFPMPool{{
			ConfigPath:  "/etc/php/8.3/fpm/pool.d/shop.conf",
			Name:        "shop",
			User:        "app-shop",
			Group:       "app-shop",
			Listen:      "/run/php/shop.sock",
			ListenOwner: "app-shop",
			ListenGroup: "app-shop",
			ListenMode:  "0660",
		}},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if len(result.Findings) != 1 || result.Findings[0].Title != "PHP-FPM socket uses the same user or group as the PHP runtime" {
		t.Fatalf("expected collapsed socket boundary finding, got %+v", result.Findings)
	}
}

func TestPHPFPMSecurityCheckReportsInheritedServiceEnvironment(t *testing.T) {
	t.Parallel()

	result, err := checks.PHPFPMSecurityCheck{}.Run(context.Background(), model.ExecutionContext{}, model.Snapshot{
		PHPFPMPools: []model.PHPFPMPool{{
			ConfigPath: "/etc/php/8.3/fpm/pool.d/shop.conf",
			Name:       "shop",
			User:       "app-shop",
			Group:      "app-shop",
			Listen:     "/run/php/shop.sock",
			ClearEnv:   "no",
		}},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if len(result.Findings) != 2 {
		t.Fatalf("expected inherited-environment and missing-socket-acl findings, got %+v", result.Findings)
	}
	if !findingTitleExists(result.Findings, "PHP-FPM workers inherit the parent service environment") {
		t.Fatalf("expected inherited environment finding, got %+v", result.Findings)
	}
}

func TestPHPFPMSecurityCheckReportsSocketACLDriftFromObservedNginxIdentity(t *testing.T) {
	t.Parallel()

	result, err := checks.PHPFPMSecurityCheck{}.Run(context.Background(), model.ExecutionContext{}, model.Snapshot{
		NginxSites: []model.NginxSite{{
			ConfigPath:         "/etc/nginx/sites-enabled/shop.conf",
			Root:               "/var/www/shop/public",
			FastCGIPassTargets: []string{"unix:/run/php/shop.sock"},
		}},
		PHPFPMPools: []model.PHPFPMPool{{
			ConfigPath:  "/etc/php/8.3/fpm/pool.d/shop.conf",
			Name:        "shop",
			User:        "app-shop",
			Group:       "app-shop",
			Listen:      "/run/php/shop.sock",
			ListenOwner: "app-shop",
			ListenGroup: "app-shop",
			ListenMode:  "0660",
		}},
		SystemdUnits: []model.SystemdUnit{{
			Path:      "/etc/systemd/system/nginx.service",
			Name:      "nginx.service",
			User:      "nginx",
			Group:     "nginx",
			ExecStart: "/usr/sbin/nginx -g daemon off;",
		}},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if len(result.Findings) != 2 {
		t.Fatalf("expected socket boundary drift and collapsed boundary findings, got %+v", result.Findings)
	}
	if !findingTitleExists(result.Findings, "Web server user does not match PHP-FPM socket permissions") {
		t.Fatalf("expected observed nginx socket-boundary finding, got %+v", result.Findings)
	}
}

func TestPHPFPMSecurityCheckIgnoresRootOnlyNginxServiceIdentity(t *testing.T) {
	t.Parallel()

	result, err := checks.PHPFPMSecurityCheck{}.Run(context.Background(), model.ExecutionContext{}, model.Snapshot{
		NginxSites: []model.NginxSite{{
			ConfigPath:         "/etc/nginx/sites-enabled/shop.conf",
			Root:               "/var/www/shop/public",
			FastCGIPassTargets: []string{"unix:/run/php/shop.sock"},
		}},
		PHPFPMPools: []model.PHPFPMPool{{
			ConfigPath:  "/etc/php/8.3/fpm/pool.d/shop.conf",
			Name:        "shop",
			User:        "app-shop",
			Group:       "app-shop",
			Listen:      "/run/php/shop.sock",
			ListenOwner: "app-shop",
			ListenGroup: "app-shop",
			ListenMode:  "0660",
		}},
		SystemdUnits: []model.SystemdUnit{{
			Path:      "/etc/systemd/system/nginx.service",
			Name:      "nginx.service",
			User:      "root",
			Group:     "root",
			ExecStart: "/usr/sbin/nginx -g daemon off;",
		}},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if len(result.Findings) != 1 {
		t.Fatalf("expected only collapsed socket boundary finding, got %+v", result.Findings)
	}
	if result.Findings[0].Title != "PHP-FPM socket uses the same user or group as the PHP runtime" {
		t.Fatalf("expected collapsed socket boundary finding, got %+v", result.Findings)
	}
}

func TestPHPFPMSecurityCheckUsesNginxAndPoolExtensionContext(t *testing.T) {
	t.Parallel()

	app := completeLaravelApp("/var/www/shop")

	result, err := checks.PHPFPMSecurityCheck{}.Run(context.Background(), model.ExecutionContext{}, model.Snapshot{
		Apps: []model.LaravelApp{app},
		NginxSites: []model.NginxSite{{
			ConfigPath:            "/etc/nginx/sites-enabled/shop.conf",
			Root:                  "/var/www/shop/public",
			HasGenericPHPLocation: true,
			FastCGIPassTargets:    []string{"unix:/run/php/shop.sock"},
		}},
		PHPFPMPools: []model.PHPFPMPool{{
			ConfigPath:              "/etc/php/8.3/fpm/pool.d/shop.conf",
			Name:                    "shop",
			User:                    "app-shop",
			Group:                   "app-shop",
			Listen:                  "/run/php/shop.sock",
			ListenOwner:             "www-data",
			ListenGroup:             "www-data",
			ListenMode:              "0660",
			SecurityLimitExtensions: []string{".php", ".phar", ".phtml"},
		}},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if !findingTitleExists(result.Findings, "Nginx and PHP-FPM together allow extra executable PHP extensions") {
		t.Fatalf("expected broad limit_extensions finding, got %+v", result.Findings)
	}
}

func TestPHPFPMSecurityCheckUsesNginxAndPHPINIContext(t *testing.T) {
	t.Parallel()

	app := completeLaravelApp("/var/www/shop")

	result, err := checks.PHPFPMSecurityCheck{}.Run(context.Background(), model.ExecutionContext{}, model.Snapshot{
		Apps: []model.LaravelApp{app},
		NginxSites: []model.NginxSite{{
			ConfigPath:            "/etc/nginx/sites-enabled/shop.conf",
			Root:                  "/var/www/shop/public",
			HasGenericPHPLocation: true,
			FastCGIPassTargets:    []string{"unix:/run/php/shop.sock"},
		}},
		PHPFPMPools: []model.PHPFPMPool{{
			ConfigPath:  "/etc/php/8.3/fpm/pool.d/shop.conf",
			Name:        "shop",
			User:        "app-shop",
			Group:       "app-shop",
			Listen:      "/run/php/shop.sock",
			ListenOwner: "www-data",
			ListenGroup: "www-data",
			ListenMode:  "0660",
		}},
		PHPINIConfigs: []model.PHPINIConfig{{
			ConfigPath:     "/etc/php/8.3/fpm/php.ini",
			CGIFixPathinfo: "1",
		}},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if !findingTitleExists(result.Findings, "Generic PHP execution is paired with cgi.fix_pathinfo=1") {
		t.Fatalf("expected cgi.fix_pathinfo context finding, got %+v", result.Findings)
	}
}
