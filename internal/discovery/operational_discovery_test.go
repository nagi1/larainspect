package discovery

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nagi1/larainspect/internal/model"
)

func TestParseSupervisorConfigParsesProgramsAndHTTPServer(t *testing.T) {
	t.Parallel()

	programs, httpServers, err := parseSupervisorConfig("/etc/supervisor/conf.d/laravel.conf", `
[program:laravel-worker]
command=/usr/bin/php /var/www/shop/current/artisan queue:work
user=deploy
directory=/var/www/shop/current
autostart=true

[inet_http_server]
port=0.0.0.0:9001
username=admin
password=secret
`)
	if err != nil {
		t.Fatalf("parseSupervisorConfig() error = %v", err)
	}

	if len(programs) != 1 || programs[0].Name != "laravel-worker" || programs[0].Directory != "/var/www/shop/current" {
		t.Fatalf("unexpected supervisor programs: %+v", programs)
	}

	if len(httpServers) != 1 || httpServers[0].Bind != "0.0.0.0:9001" || !httpServers[0].PasswordConfigured {
		t.Fatalf("unexpected supervisor http servers: %+v", httpServers)
	}
}

func TestParseSystemdUnitParsesOperationalFields(t *testing.T) {
	t.Parallel()

	unit, err := parseSystemdUnit("/etc/systemd/system/laravel-worker.service", `
[Unit]
Description=Laravel queue worker

[Service]
User=www-data
Group=www-data
WorkingDirectory=/var/www/shop/current
ExecStart=/usr/bin/php artisan queue:work
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/www/shop/current/storage /var/www/shop/current/bootstrap/cache

[Install]
WantedBy=multi-user.target
`)
	if err != nil {
		t.Fatalf("parseSystemdUnit() error = %v", err)
	}

	if unit.User != "www-data" || unit.ExecStart != "/usr/bin/php artisan queue:work" || len(unit.ReadWritePaths) != 2 {
		t.Fatalf("unexpected systemd unit: %+v", unit)
	}
}

func TestParseCronEntriesParsesSystemCronFiles(t *testing.T) {
	t.Parallel()

	entries, err := parseCronEntries("/etc/cron.d/laravel", `
SHELL=/bin/sh
* * * * * deploy cd /var/www/shop/current && php artisan schedule:run
@daily root /usr/bin/php /var/www/shop/current/artisan queue:work
`)
	if err != nil {
		t.Fatalf("parseCronEntries() error = %v", err)
	}

	if len(entries) != 2 || entries[0].User != "deploy" || entries[1].Schedule != "@daily" {
		t.Fatalf("unexpected cron entries: %+v", entries)
	}
}

func TestParseCronSourceEntriesParsesDailyScripts(t *testing.T) {
	t.Parallel()

	entries, err := parseCronSourceEntries("/etc/cron.daily/backup-shop", "#!/bin/sh\n/usr/bin/mysqldump app > /var/www/shop/current/public/dump.sql\n")
	if err != nil {
		t.Fatalf("parseCronSourceEntries() error = %v", err)
	}

	if len(entries) != 1 || entries[0].Schedule != "@daily" || entries[0].User != "root" {
		t.Fatalf("unexpected cron script entries: %+v", entries)
	}
}

func TestParseListenerRecordsParsesSocketOutput(t *testing.T) {
	t.Parallel()

	listeners, err := parseListenerRecords("tcp LISTEN 0 511 0.0.0.0:6379 0.0.0.0:* users:((\"redis-server\",pid=10,fd=6))\n")
	if err != nil {
		t.Fatalf("parseListenerRecords() error = %v", err)
	}

	if len(listeners) != 1 || listeners[0].LocalPort != "6379" || len(listeners[0].ProcessNames) != 1 || listeners[0].ProcessNames[0] != "redis-server" {
		t.Fatalf("unexpected listeners: %+v", listeners)
	}
}

func TestParseSSHConfigAndSudoRulesParseRelevantSignals(t *testing.T) {
	t.Parallel()

	sshConfig, err := parseSSHConfig("/etc/ssh/sshd_config", "PermitRootLogin yes\nPasswordAuthentication yes\n")
	if err != nil {
		t.Fatalf("parseSSHConfig() error = %v", err)
	}
	if sshConfig.PermitRootLogin != "yes" || sshConfig.PasswordAuthentication != "yes" {
		t.Fatalf("unexpected ssh config: %+v", sshConfig)
	}

	sudoRules, err := parseSudoRules("/etc/sudoers.d/deploy", "deploy ALL=(ALL) NOPASSWD: ALL\n")
	if err != nil {
		t.Fatalf("parseSudoRules() error = %v", err)
	}
	if len(sudoRules) != 1 || !sudoRules[0].AllCommands || !sudoRules[0].NoPassword {
		t.Fatalf("unexpected sudo rules: %+v", sudoRules)
	}
}

func TestParseFirewallSummaryRecognizesEnabledAndDisabledStates(t *testing.T) {
	t.Parallel()

	ufwSummary, ok := parseFirewallSummary("ufw", model.CommandResult{ExitCode: 0, Stdout: "Status: inactive\n"})
	if !ok || ufwSummary.Enabled {
		t.Fatalf("unexpected ufw summary: %+v ok=%v", ufwSummary, ok)
	}

	firewalldSummary, ok := parseFirewallSummary("firewalld", model.CommandResult{ExitCode: 0, Stdout: "running\n"})
	if !ok || !firewalldSummary.Enabled {
		t.Fatalf("unexpected firewalld summary: %+v ok=%v", firewalldSummary, ok)
	}

	nftSummary, ok := parseFirewallSummary("nftables", model.CommandResult{ExitCode: 0, Stdout: "table inet filter\n"})
	if !ok || !nftSummary.Enabled {
		t.Fatalf("unexpected nftables summary: %+v ok=%v", nftSummary, ok)
	}
}

func TestParseListenerCommandResultReturnsUnknownsForFailedAndInvalidOutput(t *testing.T) {
	t.Parallel()

	request := model.CommandRequest{Name: "ss", Args: []string{"-H", "-l"}}
	if _, unknown := parseListenerCommandResult(model.CommandResult{ExitCode: 1, Stderr: "permission denied"}, request); unknown == nil || unknown.Error != model.ErrorKindCommandFailed {
		t.Fatalf("expected command-failed unknown, got %+v", unknown)
	}

	if _, unknown := parseListenerCommandResult(model.CommandResult{ExitCode: 0, Stdout: "bad"}, request); unknown == nil || unknown.Error != model.ErrorKindParseFailure {
		t.Fatalf("expected parse-failure unknown, got %+v", unknown)
	}
}

func TestDiscoverFirewallSummariesCollectsSummariesAndUnknowns(t *testing.T) {
	t.Parallel()

	service := newTestSnapshotService()
	service.discoverFirewall = true
	service.lookPath = func(name string) (string, error) {
		switch name {
		case "ufw", "iptables":
			return "/usr/bin/" + name, nil
		default:
			return "", os.ErrNotExist
		}
	}
	service.runCommand = func(_ context.Context, command model.CommandRequest) (model.CommandResult, error) {
		switch command.Name {
		case "ufw":
			return model.CommandResult{ExitCode: 0, Stdout: "Status: inactive\n"}, nil
		case "iptables":
			return model.CommandResult{}, context.DeadlineExceeded
		default:
			return model.CommandResult{}, nil
		}
	}

	summaries, unknowns := service.discoverFirewallSummaries(context.Background())
	if len(summaries) != 1 || summaries[0].Source != "ufw" {
		t.Fatalf("unexpected firewall summaries: %+v", summaries)
	}
	if len(unknowns) != 1 || unknowns[0].Error != model.ErrorKindCommandTimeout {
		t.Fatalf("unexpected firewall unknowns: %+v", unknowns)
	}
}

func TestOperationalDiscoveryHelpersCoverFormattingPaths(t *testing.T) {
	t.Parallel()

	if got := commandSummary(model.CommandRequest{Name: "ss", Args: []string{"-H", "-l"}}); got != "ss -H -l" {
		t.Fatalf("commandSummary() = %q", got)
	}
	if got := commandSummary(model.CommandRequest{Name: "ufw"}); got != "ufw" {
		t.Fatalf("commandSummary() without args = %q", got)
	}

	unknown := newNamedCommandUnknown("Unable to inspect firewall state", context.DeadlineExceeded, "iptables", "iptables -S")
	if unknown.Error != model.ErrorKindCommandTimeout {
		t.Fatalf("unexpected unknown %+v", unknown)
	}

	commandUnknown := newCommandUnknown("Unable to inspect listeners", os.ErrPermission)
	if commandUnknown.Error != model.ErrorKindCommandFailed || commandUnknown.Evidence[0].Detail != "ss -H -l -n -t -u -p" {
		t.Fatalf("unexpected command unknown %+v", commandUnknown)
	}

	if got := firstOutputLine("first\nsecond"); got != "first" {
		t.Fatalf("firstOutputLine() = %q", got)
	}
	if got := firstOutputLine("   "); got != "" {
		t.Fatalf("firstOutputLine() blank = %q", got)
	}

	if address, port := splitListenerAddress("[::1]:9000"); address != "::1" || port != "9000" {
		t.Fatalf("splitListenerAddress() = %q %q", address, port)
	}
	if address, port := splitListenerAddress("unix"); address != "unix" || port != "" {
		t.Fatalf("splitListenerAddress() bare value = %q %q", address, port)
	}

	if user := cronUserForScriptPath("/var/spool/cron/deploy"); user != "deploy" {
		t.Fatalf("cronUserForScriptPath() = %q", user)
	}
}

func TestDiscoverListenersFromCommandHandlesUnavailableToolAndTimeout(t *testing.T) {
	t.Parallel()

	service := newTestSnapshotService()
	service.discoverListeners = true
	service.lookPath = func(name string) (string, error) {
		return "", os.ErrNotExist
	}

	listeners, unknowns := service.discoverListenersFromCommand(context.Background())
	if len(listeners) != 0 || len(unknowns) != 0 {
		t.Fatalf("expected no listeners and no unknowns when ss is unavailable, got listeners=%+v unknowns=%+v", listeners, unknowns)
	}

	service.lookPath = func(name string) (string, error) {
		return "/usr/bin/ss", nil
	}
	service.runCommand = func(_ context.Context, command model.CommandRequest) (model.CommandResult, error) {
		return model.CommandResult{}, context.DeadlineExceeded
	}

	listeners, unknowns = service.discoverListenersFromCommand(context.Background())
	if len(listeners) != 0 {
		t.Fatalf("expected no listeners on timeout, got %+v", listeners)
	}
	if len(unknowns) != 1 || unknowns[0].Error != model.ErrorKindCommandTimeout {
		t.Fatalf("expected timeout unknown, got %+v", unknowns)
	}
}

func TestSnapshotServiceDiscoversOperationalConfigsAndListeners(t *testing.T) {
	t.Parallel()

	configRoot := t.TempDir()
	supervisorConfigPath := filepath.Join(configRoot, "supervisor", "laravel.conf")
	systemdUnitPath := filepath.Join(configRoot, "systemd", "laravel-worker.service")
	cronConfigPath := filepath.Join(configRoot, "cron.d", "laravel")
	sshConfigPath := filepath.Join(configRoot, "ssh", "sshd_config")
	sudoersPath := filepath.Join(configRoot, "sudoers.d", "deploy")

	for _, path := range []string{supervisorConfigPath, systemdUnitPath, cronConfigPath, sshConfigPath, sudoersPath} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("MkdirAll(%q) error = %v", path, err)
		}
	}

	writeTestFile(t, supervisorConfigPath, "[program:worker]\ncommand=/usr/bin/php /var/www/shop/current/artisan queue:work\nuser=root\n")
	writeTestFile(t, systemdUnitPath, "[Service]\nUser=www-data\nWorkingDirectory=/var/www/shop/current\nExecStart=/usr/bin/php artisan schedule:run\n")
	writeTestFile(t, cronConfigPath, "* * * * * deploy cd /var/www/shop/current && php artisan schedule:run\n")
	writeTestFile(t, sshConfigPath, "PermitRootLogin no\nPasswordAuthentication no\n")
	writeTestFile(t, sudoersPath, "deploy ALL=(ALL) /usr/bin/systemctl reload php8.3-fpm\n")

	service := newTestSnapshotService()
	service.supervisorPatterns = []string{supervisorConfigPath}
	service.systemdPatterns = []string{systemdUnitPath}
	service.cronPatterns = []string{cronConfigPath}
	service.sshPatterns = []string{sshConfigPath}
	service.sudoersPatterns = []string{sudoersPath}
	service.discoverSupervisor = true
	service.discoverSystemd = true
	service.discoverCron = true
	service.discoverListeners = true
	service.discoverSSH = true
	service.discoverSudo = true
	service.discoverFirewall = true
	service.lookPath = func(name string) (string, error) {
		switch name {
		case "ss", "ufw":
			return "/usr/bin/ss", nil
		default:
			return "", os.ErrNotExist
		}
	}
	service.runCommand = func(_ context.Context, command model.CommandRequest) (model.CommandResult, error) {
		if len(command.Args) == 1 && command.Args[0] == "status" {
			return model.CommandResult{
				ExitCode:   0,
				Stdout:     "Status: active\n",
				Duration:   time.Millisecond.String(),
				StartedAt:  time.Unix(1700000000, 0),
				FinishedAt: time.Unix(1700000000, int64(time.Millisecond)),
			}, nil
		}
		return model.CommandResult{
			ExitCode:   0,
			Stdout:     "tcp LISTEN 0 511 0.0.0.0:6379 0.0.0.0:* users:((\"redis-server\",pid=10,fd=6))\n",
			Duration:   time.Millisecond.String(),
			StartedAt:  time.Unix(1700000000, 0),
			FinishedAt: time.Unix(1700000000, int64(time.Millisecond)),
		}, nil
	}

	snapshot, unknowns, err := service.Discover(context.Background(), model.ExecutionContext{
		Config: model.AuditConfig{Scope: model.ScanScopeHost},
	})
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}

	if len(unknowns) != 0 {
		t.Fatalf("expected no unknowns, got %+v", unknowns)
	}

	if len(snapshot.SupervisorPrograms) != 1 || len(snapshot.SystemdUnits) != 1 || len(snapshot.CronEntries) != 1 || len(snapshot.Listeners) != 1 || len(snapshot.SSHConfigs) != 1 || len(snapshot.SudoRules) != 1 || len(snapshot.FirewallSummaries) != 1 {
		t.Fatalf("unexpected operational snapshot: %+v", snapshot)
	}
}

func TestCollectArtifactRecordsSkipsExpectedLaravelWritablePHPFiles(t *testing.T) {
	t.Parallel()

	rootPath := t.TempDir()
	for _, relativePath := range []string{
		"bootstrap/cache",
		"storage/framework/views",
		"storage/app",
	} {
		if err := os.MkdirAll(filepath.Join(rootPath, relativePath), 0o755); err != nil {
			t.Fatalf("MkdirAll(%q) error = %v", relativePath, err)
		}
	}

	writeTestFile(t, filepath.Join(rootPath, "bootstrap/cache/config.php"), "<?php return [];\n")
	writeTestFile(t, filepath.Join(rootPath, "storage/framework/views/abc123.php"), "<?php echo 'cached';\n")
	writeTestFile(t, filepath.Join(rootPath, "storage/app/shell.php"), "<?php system($_GET['x']);\n")

	service := newTestSnapshotService()
	artifacts, unknowns := service.collectArtifactRecords(context.Background(), rootPath)
	if len(unknowns) != 0 {
		t.Fatalf("expected no unknowns, got %+v", unknowns)
	}

	if len(artifacts) != 1 || artifacts[0].Kind != model.ArtifactKindWritablePHPFile || artifacts[0].Path.RelativePath != "storage/app/shell.php" {
		t.Fatalf("unexpected artifacts: %+v", artifacts)
	}
}
