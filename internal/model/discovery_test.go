package model_test

import (
	"testing"

	"github.com/nagi/larainspect/internal/model"
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
