package model_test

import (
	"testing"

	"github.com/nagi1/larainspect/internal/model"
)

func TestSortPackageRecordsOrdersByNameThenSource(t *testing.T) {
	t.Parallel()

	records := []model.PackageRecord{
		{Name: "laravel/framework", Source: "z"},
		{Name: "filament/filament", Source: "b"},
		{Name: "filament/filament", Source: "a"},
	}

	model.SortPackageRecords(records)

	want := []model.PackageRecord{
		{Name: "filament/filament", Source: "a"},
		{Name: "filament/filament", Source: "b"},
		{Name: "laravel/framework", Source: "z"},
	}

	for index := range want {
		if records[index] != want[index] {
			t.Fatalf("SortPackageRecords()[%d] = %+v, want %+v", index, records[index], want[index])
		}
	}
}

func TestPathRecordHelpers(t *testing.T) {
	t.Parallel()

	record := model.PathRecord{
		PathKind:    model.PathKindSymlink,
		TargetKind:  model.PathKindFile,
		Inspected:   true,
		Exists:      true,
		Permissions: 0o644,
	}

	if !record.IsSymlink() {
		t.Fatal("expected symlink helper to report true")
	}

	if !record.IsRegularFile() {
		t.Fatal("expected effective file kind for symlink target")
	}

	if record.IsWorldWritable() {
		t.Fatal("expected non-world-writable permissions")
	}

	if !record.IsWorldReadable() {
		t.Fatal("expected world-readable permissions")
	}
	if !record.IsOwnerWritable() {
		t.Fatal("expected owner write helper to reflect 0644 permissions")
	}
	if record.IsGroupWritable() {
		t.Fatal("expected group write helper to reflect 0644 permissions")
	}

	if got := record.ModeOctal(); got != "0644" {
		t.Fatalf("ModeOctal() = %q, want 0644", got)
	}

	writableRecord := model.PathRecord{
		Inspected:   true,
		Exists:      true,
		Permissions: 0o660,
	}
	if !writableRecord.IsOwnerWritable() || !writableRecord.IsGroupWritable() {
		t.Fatalf("expected writable helpers for 0660, got %+v", writableRecord)
	}

	directoryRecord := model.PathRecord{
		PathKind:  model.PathKindDirectory,
		Inspected: true,
		Exists:    true,
	}
	if !directoryRecord.IsDirectory() {
		t.Fatal("expected IsDirectory() to report true")
	}
}

func TestCoreLaravelPathExpectationsAndSortHelpers(t *testing.T) {
	t.Parallel()

	expectations := model.CoreLaravelPathExpectations()
	if len(expectations) == 0 {
		t.Fatal("expected core Laravel path expectations")
	}

	pathRecords := []model.PathRecord{
		{RelativePath: "routes"},
		{RelativePath: "app"},
	}
	model.SortPathRecords(pathRecords)
	if pathRecords[0].RelativePath != "app" {
		t.Fatalf("SortPathRecords() did not sort as expected: %+v", pathRecords)
	}

	artifactRecords := []model.ArtifactRecord{
		{Path: model.PathRecord{RelativePath: "public/z.sql"}},
		{Path: model.PathRecord{RelativePath: "public/a.sql"}},
	}
	model.SortArtifactRecords(artifactRecords)
	if artifactRecords[0].Path.RelativePath != "public/a.sql" {
		t.Fatalf("SortArtifactRecords() did not sort as expected: %+v", artifactRecords)
	}

	sourceMatches := []model.SourceMatch{
		{RelativePath: "routes/web.php", Line: 12, RuleID: "z"},
		{RelativePath: "app/Livewire/EditUser.php", Line: 4, RuleID: "a"},
		{RelativePath: "routes/web.php", Line: 8, RuleID: "b"},
	}
	model.SortSourceMatches(sourceMatches)
	if sourceMatches[0].RelativePath != "app/Livewire/EditUser.php" || sourceMatches[1].Line != 8 {
		t.Fatalf("SortSourceMatches() did not sort as expected: %+v", sourceMatches)
	}

	nginxSites := []model.NginxSite{
		{ConfigPath: "b.conf", Root: "/b"},
		{ConfigPath: "a.conf", Root: "/a"},
	}
	model.SortNginxSites(nginxSites)
	if nginxSites[0].ConfigPath != "a.conf" {
		t.Fatalf("SortNginxSites() did not sort as expected: %+v", nginxSites)
	}

	pools := []model.PHPFPMPool{
		{ConfigPath: "b.conf", Name: "b"},
		{ConfigPath: "a.conf", Name: "a"},
	}
	model.SortPHPFPMPools(pools)
	if pools[0].ConfigPath != "a.conf" {
		t.Fatalf("SortPHPFPMPools() did not sort as expected: %+v", pools)
	}

	mysqlConfigs := []model.MySQLConfig{
		{ConfigPath: "b.cnf", Section: "mysqld"},
		{ConfigPath: "a.cnf", Section: "client"},
	}
	model.SortMySQLConfigs(mysqlConfigs)
	if mysqlConfigs[0].ConfigPath != "a.cnf" {
		t.Fatalf("SortMySQLConfigs() did not sort as expected: %+v", mysqlConfigs)
	}

	supervisorPrograms := []model.SupervisorProgram{
		{ConfigPath: "b.conf", Name: "b"},
		{ConfigPath: "a.conf", Name: "a"},
	}
	model.SortSupervisorPrograms(supervisorPrograms)
	if supervisorPrograms[0].ConfigPath != "a.conf" {
		t.Fatalf("SortSupervisorPrograms() did not sort as expected: %+v", supervisorPrograms)
	}

	supervisorHTTPServers := []model.SupervisorHTTPServer{
		{ConfigPath: "b.conf", Bind: "b"},
		{ConfigPath: "a.conf", Bind: "a"},
	}
	model.SortSupervisorHTTPServers(supervisorHTTPServers)
	if supervisorHTTPServers[0].ConfigPath != "a.conf" {
		t.Fatalf("SortSupervisorHTTPServers() did not sort as expected: %+v", supervisorHTTPServers)
	}

	systemdUnits := []model.SystemdUnit{
		{Path: "b.service", Name: "b"},
		{Path: "a.service", Name: "a"},
	}
	model.SortSystemdUnits(systemdUnits)
	if systemdUnits[0].Path != "a.service" {
		t.Fatalf("SortSystemdUnits() did not sort as expected: %+v", systemdUnits)
	}

	cronEntries := []model.CronEntry{
		{SourcePath: "b", Schedule: "z", Command: "b"},
		{SourcePath: "a", Schedule: "a", Command: "a"},
	}
	model.SortCronEntries(cronEntries)
	if cronEntries[0].SourcePath != "a" {
		t.Fatalf("SortCronEntries() did not sort as expected: %+v", cronEntries)
	}

	listenerRecords := []model.ListenerRecord{
		{Protocol: "tcp", LocalAddress: "b", LocalPort: "81"},
		{Protocol: "tcp", LocalAddress: "a", LocalPort: "80"},
	}
	model.SortListenerRecords(listenerRecords)
	if listenerRecords[0].LocalAddress != "a" {
		t.Fatalf("SortListenerRecords() did not sort as expected: %+v", listenerRecords)
	}

	sshConfigs := []model.SSHConfig{{Path: "b"}, {Path: "a"}}
	model.SortSSHConfigs(sshConfigs)
	if sshConfigs[0].Path != "a" {
		t.Fatalf("SortSSHConfigs() did not sort as expected: %+v", sshConfigs)
	}

	sudoRules := []model.SudoRule{{Path: "b", Principal: "b"}, {Path: "a", Principal: "a"}}
	model.SortSudoRules(sudoRules)
	if sudoRules[0].Path != "a" {
		t.Fatalf("SortSudoRules() did not sort as expected: %+v", sudoRules)
	}

	firewallSummaries := []model.FirewallSummary{{Source: "ufw"}, {Source: "firewalld"}}
	model.SortFirewallSummaries(firewallSummaries)
	if firewallSummaries[0].Source != "firewalld" {
		t.Fatalf("SortFirewallSummaries() did not sort as expected: %+v", firewallSummaries)
	}
}

func TestLaravelAppPathRecordLookup(t *testing.T) {
	t.Parallel()

	app := model.LaravelApp{
		KeyPaths: []model.PathRecord{{RelativePath: ".env"}},
	}

	if _, found := app.PathRecord("config"); found {
		t.Fatal("expected missing path lookup to fail")
	}

	if pathRecord, found := app.PathRecord(".env"); !found || pathRecord.RelativePath != ".env" {
		t.Fatalf("unexpected PathRecord() result: %+v found=%v", pathRecord, found)
	}
}

func TestLaravelAppDisplayAndVersionHelpers(t *testing.T) {
	t.Parallel()

	namedApp := model.LaravelApp{
		AppName:        "acme/shop",
		LaravelVersion: "v11.9.0",
		Packages: []model.PackageRecord{
			{Name: "laravel/framework", Version: "v11.8.0"},
		},
	}
	if got := namedApp.DisplayName(); got != "acme/shop" {
		t.Fatalf("DisplayName() = %q", got)
	}
	if got := namedApp.PackageVersion("laravel/framework"); got != "v11.8.0" {
		t.Fatalf("PackageVersion() = %q", got)
	}
	if got := namedApp.EffectiveLaravelVersion(); got != "v11.9.0" {
		t.Fatalf("EffectiveLaravelVersion() = %q", got)
	}

	pathApp := model.LaravelApp{
		ResolvedPath: "/srv/www/current",
		RootPath:     "/srv/www/shop",
		Packages: []model.PackageRecord{
			{Name: "laravel/framework", Version: "v11.7.0"},
		},
	}
	if got := pathApp.DisplayName(); got != "current" {
		t.Fatalf("DisplayName() path fallback = %q", got)
	}
	if got := pathApp.EffectiveLaravelVersion(); got != "v11.7.0" {
		t.Fatalf("EffectiveLaravelVersion() fallback = %q", got)
	}
	if got := (model.LaravelApp{}).DisplayName(); got != "unknown" {
		t.Fatalf("DisplayName() zero app = %q", got)
	}
}
