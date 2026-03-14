package checks_test

import (
	"context"
	"testing"

	"github.com/nagi1/larainspect/internal/checks"
	"github.com/nagi1/larainspect/internal/model"
)

func TestWorkerSchedulerCheckReportsRootWorkersAndDuplicateSchedulers(t *testing.T) {
	t.Parallel()

	app := completeLaravelApp("/var/www/shop/current")

	result, err := checks.WorkerSchedulerCheck{}.Run(context.Background(), model.ExecutionContext{}, model.Snapshot{
		Apps: []model.LaravelApp{app},
		SystemdUnits: []model.SystemdUnit{
			{
				Path:             "/etc/systemd/system/laravel-worker.service",
				Name:             "laravel-worker.service",
				User:             "root",
				WorkingDirectory: app.RootPath,
				ExecStart:        "/usr/bin/php artisan queue:work",
			},
		},
		CronEntries: []model.CronEntry{
			{
				SourcePath: "/etc/cron.d/laravel",
				Schedule:   "* * * * *",
				User:       "root",
				Command:    "cd /var/www/shop/current && php artisan schedule:run",
			},
		},
		SupervisorPrograms: []model.SupervisorProgram{
			{
				ConfigPath: "/etc/supervisor/conf.d/laravel.conf",
				Name:       "scheduler",
				User:       "deploy",
				Directory:  app.RootPath,
				Command:    "/usr/bin/php artisan schedule:run",
			},
		},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if len(result.Findings) != 3 {
		t.Fatalf("expected 3 findings, got %+v", result.Findings)
	}
}

func TestWorkerSchedulerCheckReportsStaleReleaseReference(t *testing.T) {
	t.Parallel()

	app := completeLaravelApp("/var/www/shop/current")
	app.ResolvedPath = "/var/www/shop/releases/20260312"
	app.Deployment = model.DeploymentInfo{
		UsesReleaseLayout: true,
		CurrentPath:       app.RootPath,
		ReleaseRoot:       "/var/www/shop/releases",
		SharedPath:        "/var/www/shop/shared",
		PreviousReleases: []model.PathRecord{
			{
				RelativePath: "20260310",
				AbsolutePath: "/var/www/shop/releases/20260310",
				PathKind:     model.PathKindDirectory,
				TargetKind:   model.PathKindDirectory,
				Inspected:    true,
				Exists:       true,
				Permissions:  0o755,
			},
		},
	}

	result, err := checks.WorkerSchedulerCheck{}.Run(context.Background(), model.ExecutionContext{}, model.Snapshot{
		Apps: []model.LaravelApp{app},
		SystemdUnits: []model.SystemdUnit{{
			Path:             "/etc/systemd/system/laravel-worker.service",
			Name:             "laravel-worker.service",
			User:             "www-data",
			WorkingDirectory: "/var/www/shop/releases/20260310",
			ExecStart:        "/usr/bin/php /var/www/shop/releases/20260310/artisan queue:work",
		}},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %+v", result.Findings)
	}
}

func TestOperationalNetworkCheckReportsBroadListenersAndSupervisorHTTP(t *testing.T) {
	t.Parallel()

	result, err := checks.OperationalNetworkCheck{}.Run(context.Background(), model.ExecutionContext{
		Config: model.AuditConfig{Scope: model.ScanScopeHost},
	}, model.Snapshot{
		Listeners: []model.ListenerRecord{
			{
				Protocol:     "tcp",
				LocalAddress: "0.0.0.0",
				LocalPort:    "6379",
				ProcessNames: []string{"redis-server"},
			},
		},
		SupervisorHTTPServers: []model.SupervisorHTTPServer{
			{
				ConfigPath:         "/etc/supervisor/supervisord.conf",
				Bind:               "0.0.0.0:9001",
				PasswordConfigured: false,
			},
		},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if len(result.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %+v", result.Findings)
	}

	if result.Findings[1].Severity != model.SeverityCritical {
		t.Fatalf("expected critical supervisor finding, got %+v", result.Findings[1])
	}
}

func TestOperationalNetworkCheckCoversAdditionalBroadOperationalServices(t *testing.T) {
	t.Parallel()

	result, err := checks.OperationalNetworkCheck{}.Run(context.Background(), model.ExecutionContext{
		Config: model.AuditConfig{Scope: model.ScanScopeHost},
	}, model.Snapshot{
		Listeners: []model.ListenerRecord{
			{Protocol: "tcp", LocalAddress: "0.0.0.0", LocalPort: "3306", ProcessNames: []string{"mysqld"}},
			{Protocol: "tcp", LocalAddress: "0.0.0.0", LocalPort: "5432", ProcessNames: []string{"postgres"}},
			{Protocol: "tcp", LocalAddress: "0.0.0.0", LocalPort: "9000", ProcessNames: []string{"php-fpm8.3"}},
			{Protocol: "tcp", LocalAddress: "0.0.0.0", LocalPort: "8000", ProcessNames: []string{"php"}},
			{Protocol: "tcp", LocalAddress: "0.0.0.0", LocalPort: "6001", ProcessNames: []string{"node"}},
			{Protocol: "tcp", LocalAddress: "127.0.0.1", LocalPort: "6379", ProcessNames: []string{"redis-server"}},
		},
		SupervisorHTTPServers: []model.SupervisorHTTPServer{
			{
				ConfigPath:         "/etc/supervisor/conf.d/inet.conf",
				Bind:               "0.0.0.0:9001",
				Username:           "admin",
				PasswordConfigured: true,
			},
		},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if len(result.Findings) != 6 {
		t.Fatalf("expected 6 findings, got %+v", result.Findings)
	}

	lastFinding := result.Findings[len(result.Findings)-1]
	if lastFinding.Severity != model.SeverityHigh {
		t.Fatalf("expected authenticated supervisor finding to stay high severity, got %+v", lastFinding)
	}
}

func TestOperationalNetworkCheckReturnsNoFindingsForAppScopeWithoutApps(t *testing.T) {
	t.Parallel()

	result, err := checks.OperationalNetworkCheck{}.Run(context.Background(), model.ExecutionContext{
		Config: model.AuditConfig{Scope: model.ScanScopeApp},
	}, model.Snapshot{
		Listeners: []model.ListenerRecord{{
			Protocol:     "tcp",
			LocalAddress: "0.0.0.0",
			LocalPort:    "6379",
			ProcessNames: []string{"redis-server"},
		}},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings without apps in app scope, got %+v", result.Findings)
	}
}

func TestOperationalDeployCheckReportsVersionControlComposerAndDangerousPermissionDrift(t *testing.T) {
	t.Parallel()

	app := completeLaravelApp("/var/www/shop/current")
	app.Artifacts = []model.ArtifactRecord{
		{
			Kind: model.ArtifactKindVersionControlPath,
			Path: model.PathRecord{
				RelativePath: ".git",
				AbsolutePath: "/var/www/shop/current/.git",
				PathKind:     model.PathKindDirectory,
				TargetKind:   model.PathKindDirectory,
				Inspected:    true,
				Exists:       true,
				Permissions:  0o755,
			},
		},
	}

	result, err := checks.OperationalDeployCheck{}.Run(context.Background(), model.ExecutionContext{}, model.Snapshot{
		Apps: []model.LaravelApp{app},
		SystemdUnits: []model.SystemdUnit{
			{
				Path:             "/etc/systemd/system/deploy.service",
				Name:             "deploy.service",
				User:             "root",
				WorkingDirectory: app.RootPath,
				ExecStart:        "/usr/bin/composer install --no-dev",
			},
		},
		CronEntries: []model.CronEntry{
			{
				SourcePath: "/etc/cron.d/deploy-fixups",
				Schedule:   "@daily",
				User:       "root",
				Command:    "chown -R www-data:www-data /var/www/shop/current",
			},
		},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if len(result.Findings) != 3 {
		t.Fatalf("expected 3 findings, got %+v", result.Findings)
	}
}

func TestOperationalDeployCheckReportsMutableLiveTreeDeployment(t *testing.T) {
	t.Parallel()

	app := completeLaravelApp("/var/www/shop/current")
	app.Deployment = model.DeploymentInfo{CurrentPath: app.RootPath}

	result, err := checks.OperationalDeployCheck{}.Run(context.Background(), model.ExecutionContext{
		Config: model.AuditConfig{Scope: model.ScanScopeHost},
	}, model.Snapshot{
		Apps: []model.LaravelApp{app},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %+v", result.Findings)
	}

	finding := result.Findings[0]
	if finding.ID == "" || finding.Class != model.FindingClassHeuristic || finding.Severity != model.SeverityMedium {
		t.Fatalf("unexpected finding %+v", finding)
	}
}

func TestOperationalDeployCheckCorrelatesPostDeployDrift(t *testing.T) {
	t.Parallel()

	app := completeLaravelApp("/var/www/shop/current")
	app.RootRecord.OwnerName = "www-data"
	setPathRecord(&app, "app", model.PathKindDirectory, 0o770)
	setPathOwnership(&app, "app", "deploy", "www-data")
	setPathRecord(&app, "public/storage", model.PathKindSymlink, 0o770)
	setPathOwnership(&app, "public/storage", "deploy", "www-data")
	for index, pathRecord := range app.KeyPaths {
		if pathRecord.RelativePath != "public/storage" {
			continue
		}
		app.KeyPaths[index].ResolvedPath = "/srv/unexpected-storage"
	}
	app.Deployment = model.DeploymentInfo{
		UsesReleaseLayout: true,
		CurrentPath:       app.RootPath,
		ReleaseRoot:       "/var/www/shop/releases",
		SharedPath:        "/var/www/shop/shared",
		PreviousReleases: []model.PathRecord{{
			RelativePath: "20260310",
			AbsolutePath: "/var/www/shop/releases/20260310",
			PathKind:     model.PathKindDirectory,
			TargetKind:   model.PathKindDirectory,
			Inspected:    true,
			Exists:       true,
			Permissions:  0o775,
			OwnerName:    "deploy",
			GroupName:    "www-data",
		}},
	}

	result, err := checks.OperationalDeployCheck{}.Run(context.Background(), model.ExecutionContext{}, model.Snapshot{
		Apps: []model.LaravelApp{app},
		NginxSites: []model.NginxSite{{
			ConfigPath:         "/etc/nginx/sites-enabled/shop.conf",
			Root:               "/var/www/shop/current/public",
			FastCGIPassTargets: []string{"unix:/run/php/shop.sock"},
		}},
		PHPFPMPools: []model.PHPFPMPool{{
			ConfigPath: "/etc/php/8.3/fpm/pool.d/shop.conf",
			Name:       "shop",
			User:       "www-data",
			Group:      "www-data",
			Listen:     "/run/php/shop.sock",
			ListenMode: "0660",
		}},
		SystemdUnits: []model.SystemdUnit{{
			Path:             "/etc/systemd/system/deploy.service",
			Name:             "deploy.service",
			User:             "deploy",
			WorkingDirectory: app.RootPath,
			ExecStart:        "/usr/bin/composer install --no-dev",
		}},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if !findingTitleExists(result.Findings, "Post-deploy drift weakens Laravel ownership or writable-path boundaries") {
		t.Fatalf("expected post-deploy drift finding, got %+v", result.Findings)
	}
}

func TestOperationalDeployCheckCorrelatesPostRestoreDrift(t *testing.T) {
	t.Parallel()

	app := completeLaravelApp("/var/www/shop/current")
	setPathOwnership(&app, ".env", "www-data", "www-data")
	setPathRecord(&app, "public/storage", model.PathKindSymlink, 0o770)
	for index, pathRecord := range app.KeyPaths {
		if pathRecord.RelativePath != "public/storage" {
			continue
		}
		app.KeyPaths[index].ResolvedPath = "/tmp/recovered-files"
	}
	app.Artifacts = []model.ArtifactRecord{{
		Kind:             model.ArtifactKindEnvironmentBackup,
		WithinPublicPath: true,
		Path:             newArtifactPathRecord("/var/www/shop/current", "public/.env.restore.bak"),
	}}

	result, err := checks.OperationalDeployCheck{}.Run(context.Background(), model.ExecutionContext{}, model.Snapshot{
		Apps: []model.LaravelApp{app},
		SystemdUnits: []model.SystemdUnit{{
			Path:             "/etc/systemd/system/restore.service",
			Name:             "restore.service",
			User:             "deploy",
			WorkingDirectory: app.RootPath,
			ExecStart:        "/usr/local/bin/restore-laravel --app /var/www/shop/current",
		}},
		NginxSites: []model.NginxSite{{
			ConfigPath:         "/etc/nginx/sites-enabled/shop.conf",
			Root:               "/var/www/shop/current/public",
			FastCGIPassTargets: []string{"unix:/run/php/shop.sock"},
		}},
		PHPFPMPools: []model.PHPFPMPool{{
			ConfigPath: "/etc/php/8.3/fpm/pool.d/shop.conf",
			Name:       "shop",
			User:       "www-data",
			Group:      "www-data",
			Listen:     "/run/php/shop.sock",
			ListenMode: "0660",
		}},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if !findingTitleExists(result.Findings, "Post-restore drift weakens Laravel ownership, shared-path, or recovery boundaries") {
		t.Fatalf("expected post-restore drift finding, got %+v", result.Findings)
	}
}

func TestOperationalDeployCheckReportsProductionComposerFlagsAndRootRestore(t *testing.T) {
	t.Parallel()

	app := completeLaravelApp("/var/www/shop/current")
	app.Deployment = model.DeploymentInfo{
		UsesReleaseLayout: true,
		CurrentPath:       app.RootPath,
		PreviousReleases: []model.PathRecord{{
			RelativePath: "20260310",
			AbsolutePath: "/var/www/shop/releases/20260310",
			PathKind:     model.PathKindDirectory,
			TargetKind:   model.PathKindDirectory,
			Inspected:    true,
			Exists:       true,
			Permissions:  0o775,
		}},
	}

	result, err := checks.OperationalDeployCheck{}.Run(context.Background(), model.ExecutionContext{}, model.Snapshot{
		Apps: []model.LaravelApp{app},
		SystemdUnits: []model.SystemdUnit{{
			Path:             "/etc/systemd/system/deploy.service",
			Name:             "deploy.service",
			User:             "deploy",
			WorkingDirectory: app.RootPath,
			ExecStart:        "/usr/bin/composer install --prefer-dist",
		}},
		CronEntries: []model.CronEntry{{
			SourcePath: "/etc/cron.d/restore",
			Schedule:   "@daily",
			User:       "root",
			Command:    "/usr/local/bin/restore-app",
		}},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if len(result.Findings) != 3 {
		t.Fatalf("expected 3 findings, got %+v", result.Findings)
	}
}

func TestOperationalDeployCheckIgnoresUnrelatedRootRestoreCommands(t *testing.T) {
	t.Parallel()

	app := completeLaravelApp("/var/www/shop/current")

	result, err := checks.OperationalDeployCheck{}.Run(context.Background(), model.ExecutionContext{}, model.Snapshot{
		Apps: []model.LaravelApp{app},
		SystemdUnits: []model.SystemdUnit{{
			Path:      "/lib/systemd/system/nvmet.service",
			Name:      "nvmet.service",
			User:      "root",
			ExecStart: "/usr/sbin/nvmetcli restore",
		}},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	for _, finding := range result.Findings {
		if finding.Title == "Restore or artisan maintenance workflow runs as root" {
			t.Fatalf("did not expect unrelated restore command to match Laravel workflow, got %+v", result.Findings)
		}
	}
}

func TestOperationalCronCheckReportsDirectArtisanPublicOutputAndRootMaintenance(t *testing.T) {
	t.Parallel()

	app := completeLaravelApp("/var/www/shop/current")

	result, err := checks.OperationalCronCheck{}.Run(context.Background(), model.ExecutionContext{}, model.Snapshot{
		Apps: []model.LaravelApp{app},
		CronEntries: []model.CronEntry{
			{
				SourcePath: "/etc/cron.d/shop",
				Schedule:   "* * * * *",
				User:       "deploy",
				Command:    "cd /var/www/shop/current && php artisan queue:restart > /var/www/shop/current/public/cron.log",
			},
			{
				SourcePath: "/etc/cron.daily/shop-backup",
				Schedule:   "@daily",
				User:       "root",
				Command:    "mysqldump app > /var/www/shop/current/public/backup.sql",
			},
		},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if len(result.Findings) != 5 {
		t.Fatalf("expected 5 findings, got %+v", result.Findings)
	}
}

func TestOperationalForensicsCheckReportsOnlyCompromiseIndicators(t *testing.T) {
	t.Parallel()

	app := completeLaravelApp("/var/www/shop/current")
	app.Artifacts = []model.ArtifactRecord{
		{
			Kind: model.ArtifactKindWritablePHPFile,
			Path: newArtifactPathRecord("/var/www/shop/current", "storage/app/shell.php"),
		},
		{
			Kind: model.ArtifactKindWritableSymlink,
			Path: model.PathRecord{
				RelativePath: "storage/app/current",
				AbsolutePath: "/var/www/shop/current/storage/app/current",
				PathKind:     model.PathKindSymlink,
				TargetKind:   model.PathKindDirectory,
				Inspected:    true,
				Exists:       true,
				Permissions:  0o777,
			},
		},
	}

	result, err := checks.OperationalForensicsCheck{}.Run(context.Background(), model.ExecutionContext{}, model.Snapshot{
		Apps: []model.LaravelApp{app},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if len(result.Findings) != 2 {
		t.Fatalf("expected 2 indicators, got %+v", result.Findings)
	}

	for _, finding := range result.Findings {
		if finding.Class != model.FindingClassCompromiseIndicator {
			t.Fatalf("expected compromise indicator class, got %+v", finding)
		}
	}
}
