package model

import "sort"

type PackageRecord struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Source  string `json:"source,omitempty"`
}

type LaravelApp struct {
	RootPath     string          `json:"root_path"`
	ResolvedPath string          `json:"resolved_path,omitempty"`
	AppName      string          `json:"app_name,omitempty"`
	MarkerFiles  []string        `json:"marker_files"`
	Packages     []PackageRecord `json:"packages,omitempty"`
}

func SortPackageRecords(records []PackageRecord) {
	sort.Slice(records, func(leftIndex int, rightIndex int) bool {
		if records[leftIndex].Name == records[rightIndex].Name {
			return records[leftIndex].Source < records[rightIndex].Source
		}

		return records[leftIndex].Name < records[rightIndex].Name
	})
}
