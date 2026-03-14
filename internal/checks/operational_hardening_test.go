package checks_test

import (
	"context"
	"strings"
	"testing"

	"github.com/nagi1/larainspect/internal/checks"
	"github.com/nagi1/larainspect/internal/model"
)

func TestOperationalHardeningCheckReportsSSHSudoSystemdFirewallAndLogs(t *testing.T) {
	t.Parallel()

	app := completeLaravelApp("/var/www/shop/current")
	setPathRecord(&app, "storage/logs", model.PathKindDirectory, 0o755)

	result, err := checks.OperationalHardeningCheck{}.Run(context.Background(), model.ExecutionContext{}, model.Snapshot{
		Apps: []model.LaravelApp{app},
		SSHConfigs: []model.SSHConfig{{
			Path:                   "/etc/ssh/sshd_config",
			PermitRootLogin:        "yes",
			PasswordAuthentication: "yes",
		}},
		SudoRules: []model.SudoRule{{
			Path:        "/etc/sudoers.d/deploy",
			Principal:   "deploy",
			NoPassword:  true,
			AllCommands: true,
		}},
		SystemdUnits: []model.SystemdUnit{{
			Path:      "/etc/systemd/system/php-fpm.service",
			Name:      "php-fpm.service",
			ExecStart: "/usr/sbin/php-fpm --nodaemonize",
		}},
		FirewallSummaries: []model.FirewallSummary{{Source: "ufw", Enabled: false, State: "Status: inactive"}},
		Listeners: []model.ListenerRecord{{
			LocalAddress: "0.0.0.0",
			LocalPort:    "6379",
		}},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if len(result.Findings) != 8 {
		t.Fatalf("expected 8 findings, got %+v", result.Findings)
	}
}

func TestOperationalHardeningCheckReportsSSHAccountPermissionDrift(t *testing.T) {
	t.Parallel()

	result, err := checks.OperationalHardeningCheck{}.Run(context.Background(), model.ExecutionContext{}, model.Snapshot{
		SSHAccounts: []model.SSHAccount{
			{
				User: "deploy",
				SSHDir: model.PathRecord{
					AbsolutePath: "/home/deploy/.ssh",
					PathKind:     model.PathKindDirectory,
					TargetKind:   model.PathKindDirectory,
					Inspected:    true,
					Exists:       true,
					Permissions:  0o755,
				},
				AuthorizedKeys: model.PathRecord{
					AbsolutePath: "/home/deploy/.ssh/authorized_keys",
					PathKind:     model.PathKindFile,
					TargetKind:   model.PathKindFile,
					Inspected:    true,
					Exists:       true,
					Permissions:  0o644,
				},
				PrivateKeys: []model.PathRecord{{
					AbsolutePath: "/home/deploy/.ssh/id_ed25519",
					PathKind:     model.PathKindFile,
					TargetKind:   model.PathKindFile,
					Inspected:    true,
					Exists:       true,
					Permissions:  0o640,
				}},
			},
		},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if len(result.Findings) != 3 {
		t.Fatalf("expected 3 findings, got %+v", result.Findings)
	}

	for _, finding := range result.Findings {
		if finding.Severity != model.SeverityHigh {
			t.Fatalf("expected high severity finding, got %+v", finding)
		}
	}
}

func TestOperationalHardeningCheckReportsRuntimeSSHAccessAndDeployBoundaryCollapse(t *testing.T) {
	t.Parallel()

	app := completeLaravelApp("/var/www/shop/current")

	result, err := checks.OperationalHardeningCheck{}.Run(context.Background(), model.ExecutionContext{}, model.Snapshot{
		Apps: []model.LaravelApp{app},
		NginxSites: []model.NginxSite{{
			ConfigPath:         "/etc/nginx/sites-enabled/shop.conf",
			Root:               "/var/www/shop/current/public",
			FastCGIPassTargets: []string{"unix:/run/php/shop.sock"},
		}},
		PHPFPMPools: []model.PHPFPMPool{{
			ConfigPath: "/etc/php/8.3/fpm/pool.d/shop.conf",
			Name:       "shop",
			User:       "deploy",
			Group:      "www-data",
			Listen:     "/run/php/shop.sock",
		}},
		SSHAccounts: []model.SSHAccount{{
			User: "deploy",
			AuthorizedKeys: model.PathRecord{
				AbsolutePath: "/home/deploy/.ssh/authorized_keys",
				PathKind:     model.PathKindFile,
				TargetKind:   model.PathKindFile,
				Inspected:    true,
				Exists:       true,
				Permissions:  0o600,
			},
		}},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %+v", result.Findings)
	}

	finding := result.Findings[0]
	if finding.Title != "Laravel runtime user can log in over SSH" || finding.Severity != model.SeverityHigh {
		t.Fatalf("unexpected finding %+v", finding)
	}
}

func TestOperationalHardeningCheckReportsWildcardAndSensitiveSudoRules(t *testing.T) {
	t.Parallel()

	result, err := checks.OperationalHardeningCheck{}.Run(context.Background(), model.ExecutionContext{}, model.Snapshot{
		Apps: []model.LaravelApp{completeLaravelApp("/var/www/shop/current")},
		SudoRules: []model.SudoRule{
			{
				Path:       "/etc/sudoers.d/deploy-wildcard",
				Principal:  "deploy",
				Commands:   []string{"/usr/bin/systemctl restart php*-fpm"},
				NoPassword: true,
			},
			{
				Path:       "/etc/sudoers.d/deploy-service",
				Principal:  "deploy",
				Commands:   []string{"/usr/bin/systemctl reload php8.3-fpm"},
				NoPassword: true,
			},
		},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if len(result.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %+v", result.Findings)
	}

	if result.Findings[0].Severity != model.SeverityCritical {
		t.Fatalf("expected wildcard nopasswd sudo to be critical, got %+v", result.Findings[0])
	}
	if result.Findings[1].Title != "Operational user can run sensitive sudo commands without a password" {
		t.Fatalf("expected sensitive nopasswd sudo finding, got %+v", result.Findings[1])
	}
}

func TestOperationalHardeningCheckReportsLaravelWritableBoundaryDrift(t *testing.T) {
	t.Parallel()

	app := completeLaravelApp("/var/www/shop/current")

	result, err := checks.OperationalHardeningCheck{}.Run(context.Background(), model.ExecutionContext{}, model.Snapshot{
		Apps: []model.LaravelApp{app},
		SystemdUnits: []model.SystemdUnit{
			{
				Path:             "/etc/systemd/system/laravel-worker.service",
				Name:             "laravel-worker.service",
				User:             "deploy",
				WorkingDirectory: app.RootPath,
				ExecStart:        "/usr/bin/php artisan queue:work",
			},
			{
				Path:             "/etc/systemd/system/horizon.service",
				Name:             "horizon.service",
				User:             "deploy",
				WorkingDirectory: app.RootPath,
				ExecStart:        "/usr/bin/php artisan horizon",
				ReadWritePaths:   []string{app.RootPath},
			},
		},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if len(result.Findings) != 6 {
		t.Fatalf("expected 6 findings, got %+v", result.Findings)
	}

	titles := []string{}
	for _, finding := range result.Findings {
		titles = append(titles, finding.Title)
	}
	if !containsString(titles, "App-adjacent Laravel service does not declare explicit writable paths") {
		t.Fatalf("expected missing writable-path finding, got %+v", titles)
	}
	if !containsString(titles, "App-adjacent systemd unit allows overly broad Laravel write paths") {
		t.Fatalf("expected broad writable-path finding, got %+v", titles)
	}
}

func TestOperationalHardeningCheckReportsCollapsedDeployRuntimeSSHIdentity(t *testing.T) {
	t.Parallel()

	app := completeLaravelApp("/var/www/shop/current")
	app.RootRecord.OwnerName = "deploy"

	result, err := checks.OperationalHardeningCheck{}.Run(context.Background(), model.ExecutionContext{}, model.Snapshot{
		Apps: []model.LaravelApp{app},
		SystemdUnits: []model.SystemdUnit{{
			Path:             "/etc/systemd/system/laravel-worker.service",
			Name:             "laravel-worker.service",
			User:             "deploy",
			WorkingDirectory: app.RootPath,
			ExecStart:        "/usr/bin/php artisan queue:work",
		}},
		SSHAccounts: []model.SSHAccount{{
			User: "deploy",
			AuthorizedKeys: model.PathRecord{
				AbsolutePath: "/home/deploy/.ssh/authorized_keys",
				PathKind:     model.PathKindFile,
				TargetKind:   model.PathKindFile,
				Inspected:    true,
				Exists:       true,
				Permissions:  0o600,
			},
		}},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	runtimeSSHFinding := firstFindingByTitle(result.Findings, "Laravel runtime user can log in over SSH")
	if runtimeSSHFinding.Title == "" {
		t.Fatalf("expected runtime ssh finding, got %+v", result.Findings)
	}
	if runtimeSSHFinding.Why == "" || !strings.Contains(runtimeSSHFinding.Why, "same account appears to handle deployment") {
		t.Fatalf("expected collapsed identity explanation, got %+v", runtimeSSHFinding)
	}
}

func TestOperationalHardeningCheckDoesNotFlagNarrowLaravelWritablePaths(t *testing.T) {
	t.Parallel()

	app := completeLaravelApp("/var/www/shop/current")

	result, err := checks.OperationalHardeningCheck{}.Run(context.Background(), model.ExecutionContext{}, model.Snapshot{
		Apps: []model.LaravelApp{app},
		SystemdUnits: []model.SystemdUnit{{
			Path:             "/etc/systemd/system/laravel-worker.service",
			Name:             "laravel-worker.service",
			User:             "deploy",
			WorkingDirectory: app.RootPath,
			ExecStart:        "/usr/bin/php artisan queue:work",
			NoNewPrivileges:  "yes",
			ProtectSystem:    "strict",
			ReadWritePaths: []string{
				app.RootPath + "/storage",
				app.RootPath + "/bootstrap/cache",
			},
		}},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if len(result.Findings) != 0 {
		t.Fatalf("expected no writable-boundary findings, got %+v", result.Findings)
	}
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}

	return false
}

func firstFindingByTitle(findings []model.Finding, title string) model.Finding {
	for _, finding := range findings {
		if finding.Title == title {
			return finding
		}
	}

	return model.Finding{}
}
