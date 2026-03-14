package store_test

import (
	"os"
	"testing"
	"time"

	"github.com/nagi1/larainspect/internal/model"
	"github.com/nagi1/larainspect/internal/store"
)

func testReport(hostname string) model.Report {
	report, _ := model.BuildReport(
		model.Host{Hostname: hostname, OS: "linux", Arch: "amd64"},
		time.Date(2025, 6, 15, 10, 0, 0, 0, time.UTC),
		2*time.Second,
		[]model.Finding{
			{
				ID:          "f1",
				CheckID:     "CHECK_A",
				Class:       model.FindingClassDirect,
				Severity:    model.SeverityHigh,
				Confidence:  model.ConfidenceConfirmed,
				Title:       "Debug enabled",
				Why:         "Leaks sensitive data",
				Remediation: "Disable debug mode",
				Evidence:    []model.Evidence{{Label: "env", Detail: "APP_DEBUG=true"}},
				Affected:    []model.Target{{Type: "file", Path: "/app/.env"}},
			},
		},
		nil,
	)
	return report
}

func TestSaveAndListRecords(t *testing.T) {
	dir := t.TempDir()
	s := store.New(dir)

	report := testReport("web-01")
	record, err := s.Save(report)
	if err != nil {
		t.Fatalf("Save: %v", err)
	}

	if record.Hostname != "web-01" {
		t.Errorf("Hostname = %q, want web-01", record.Hostname)
	}
	if record.FindingCount != 1 {
		t.Errorf("FindingCount = %d, want 1", record.FindingCount)
	}

	records, err := s.ListRecords()
	if err != nil {
		t.Fatalf("ListRecords: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
}

func TestLastRecord(t *testing.T) {
	dir := t.TempDir()
	s := store.New(dir)

	_, _ = s.Save(testReport("web-01"))

	last, err := s.LastRecord("web-01")
	if err != nil {
		t.Fatalf("LastRecord: %v", err)
	}
	if last == nil {
		t.Fatal("LastRecord returned nil")
	}

	noMatch, err := s.LastRecord("other-host")
	if err != nil {
		t.Fatalf("LastRecord: %v", err)
	}
	if noMatch != nil {
		t.Error("LastRecord should return nil for unknown host")
	}
}

func TestCompareLast(t *testing.T) {
	dir := t.TempDir()
	s := store.New(dir)

	// First scan.
	report1 := testReport("web-01")
	_, _ = s.Save(report1)

	// Second scan with a different finding (simulating a new one).
	report2, _ := model.BuildReport(
		model.Host{Hostname: "web-01", OS: "linux", Arch: "amd64"},
		time.Date(2025, 6, 16, 10, 0, 0, 0, time.UTC),
		2*time.Second,
		[]model.Finding{
			{
				ID:          "f2",
				CheckID:     "CHECK_B",
				Class:       model.FindingClassDirect,
				Severity:    model.SeverityMedium,
				Confidence:  model.ConfidenceConfirmed,
				Title:       "New finding",
				Why:         "Something",
				Remediation: "Fix it",
				Evidence:    []model.Evidence{{Label: "x", Detail: "y"}},
			},
		},
		nil,
	)

	diff, err := s.CompareLast(report2)
	if err != nil {
		t.Fatalf("CompareLast: %v", err)
	}
	if diff == nil {
		t.Fatal("CompareLast returned nil diff")
	}

	if diff.TotalBefore != 1 {
		t.Errorf("TotalBefore = %d, want 1", diff.TotalBefore)
	}
	if diff.TotalAfter != 1 {
		t.Errorf("TotalAfter = %d, want 1", diff.TotalAfter)
	}
	if len(diff.NewFindings) != 1 {
		t.Errorf("expected 1 new finding, got %d", len(diff.NewFindings))
	}
	if len(diff.ResolvedFindings) != 1 {
		t.Errorf("expected 1 resolved finding, got %d", len(diff.ResolvedFindings))
	}
}

func TestCompareLast_NoHistory(t *testing.T) {
	dir := t.TempDir()
	s := store.New(dir)

	diff, err := s.CompareLast(testReport("web-01"))
	if err != nil {
		t.Fatalf("CompareLast: %v", err)
	}
	if diff != nil {
		t.Error("expected nil diff when no history exists")
	}
}

func TestListRecords_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	s := store.New(dir)

	records, err := s.ListRecords()
	if err != nil {
		t.Fatalf("ListRecords: %v", err)
	}
	if len(records) != 0 {
		t.Errorf("expected 0 records, got %d", len(records))
	}
}

func TestListRecords_SkipsNonJSONAndCorruptFiles(t *testing.T) {
	dir := t.TempDir()
	s := store.New(dir)

	// Save a valid record first.
	if _, err := s.Save(testReport("web-01")); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Write a non-JSON file (should be skipped).
	if err := os.WriteFile(dir+"/notes.txt", []byte("not json"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Write a corrupt JSON file (should be skipped).
	if err := os.WriteFile(dir+"/bad.json", []byte("{invalid"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Create a subdirectory (should be skipped).
	if err := os.Mkdir(dir+"/subdir", 0700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	records, err := s.ListRecords()
	if err != nil {
		t.Fatalf("ListRecords: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 valid record (skipping non-JSON, corrupt, and dirs), got %d", len(records))
	}
}

func TestListRecords_NonexistentDir(t *testing.T) {
	s := store.New(t.TempDir() + "/nonexistent")

	records, err := s.ListRecords()
	if err != nil {
		t.Fatalf("ListRecords: %v", err)
	}
	if records != nil {
		t.Fatalf("expected nil records for nonexistent dir, got %d", len(records))
	}
}

func TestSave_MultipleRecordsOrderedByTimestamp(t *testing.T) {
	dir := t.TempDir()
	s := store.New(dir)

	earlier, _ := model.BuildReport(
		model.Host{Hostname: "web-01"},
		time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Second, nil, nil,
	)
	later, _ := model.BuildReport(
		model.Host{Hostname: "web-01"},
		time.Date(2025, 6, 15, 0, 0, 0, 0, time.UTC),
		time.Second, nil, nil,
	)

	if _, err := s.Save(earlier); err != nil {
		t.Fatalf("Save earlier: %v", err)
	}
	if _, err := s.Save(later); err != nil {
		t.Fatalf("Save later: %v", err)
	}

	records, err := s.ListRecords()
	if err != nil {
		t.Fatalf("ListRecords: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(records))
	}
	// Most recent first.
	if !records[0].Timestamp.After(records[1].Timestamp) {
		t.Fatal("expected records ordered most-recent-first")
	}
}
