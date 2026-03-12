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

	if got := record.ModeOctal(); got != "0644" {
		t.Fatalf("ModeOctal() = %q, want 0644", got)
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
