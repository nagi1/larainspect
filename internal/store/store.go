package store

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/nagi1/larainspect/internal/model"
)

// ScanRecord is the compact on-disk representation of a completed audit.
type ScanRecord struct {
	ID             string         `json:"id"`
	Hostname       string         `json:"hostname"`
	Timestamp      time.Time      `json:"timestamp"`
	Duration       string         `json:"duration"`
	FindingCount   int            `json:"finding_count"`
	UnknownCount   int            `json:"unknown_count"`
	BySeverity     map[string]int `json:"by_severity"`
	FindingKeys    []string       `json:"finding_keys"`
}

// Diff represents the difference between two scans.
type Diff struct {
	NewFindings      []string `json:"new_findings"`
	ResolvedFindings []string `json:"resolved_findings"`
	TotalBefore      int      `json:"total_before"`
	TotalAfter       int      `json:"total_after"`
}

// Store manages scan history persistence.
type Store struct {
	Dir string
}

// New creates a store backed by the given directory. The directory is
// created on first Save if it does not exist.
func New(dir string) *Store {
	return &Store{Dir: dir}
}

// Save persists a scan record derived from the report.
func (s *Store) Save(report model.Report) (*ScanRecord, error) {
	if err := os.MkdirAll(s.Dir, 0700); err != nil {
		return nil, fmt.Errorf("creating store dir: %w", err)
	}

	findingKeys := extractFindingKeys(report)

	record := &ScanRecord{
		ID:           generateID(report),
		Hostname:     report.Host.Hostname,
		Timestamp:    report.GeneratedAt,
		Duration:     report.Duration,
		FindingCount: report.Summary.TotalFindings,
		UnknownCount: report.Summary.Unknowns,
		BySeverity:   make(map[string]int),
		FindingKeys:  findingKeys,
	}

	for sev, count := range report.Summary.SeverityCounts {
		record.BySeverity[string(sev)] = count
	}

	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encoding scan record: %w", err)
	}

	filename := fmt.Sprintf("%s_%s.json",
		record.Timestamp.Format("2006-01-02T15-04-05"),
		sanitizeName(record.Hostname))

	path := filepath.Join(s.Dir, filename)
	if err := os.WriteFile(path, data, 0600); err != nil {
		return nil, fmt.Errorf("writing scan record: %w", err)
	}

	return record, nil
}

// ListRecords returns all stored scan records, most recent first.
func (s *Store) ListRecords() ([]ScanRecord, error) {
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var records []ScanRecord
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		data, err := os.ReadFile(filepath.Join(s.Dir, entry.Name()))
		if err != nil {
			continue
		}

		var record ScanRecord
		if err := json.Unmarshal(data, &record); err != nil {
			continue
		}

		records = append(records, record)
	}

	sort.Slice(records, func(i, j int) bool {
		return records[i].Timestamp.After(records[j].Timestamp)
	})

	return records, nil
}

// LastRecord returns the most recent scan record for the given hostname.
func (s *Store) LastRecord(hostname string) (*ScanRecord, error) {
	records, err := s.ListRecords()
	if err != nil {
		return nil, err
	}

	for _, r := range records {
		if r.Hostname == hostname {
			return &r, nil
		}
	}
	return nil, nil
}

// CompareLast diffs the current report against the most recent stored
// scan for the same host.
func (s *Store) CompareLast(report model.Report) (*Diff, error) {
	last, err := s.LastRecord(report.Host.Hostname)
	if err != nil || last == nil {
		return nil, err
	}

	currentKeys := extractFindingKeys(report)
	currentSet := toSet(currentKeys)
	previousSet := toSet(last.FindingKeys)

	diff := &Diff{
		TotalBefore: last.FindingCount,
		TotalAfter:  report.Summary.TotalFindings,
	}

	for _, k := range currentKeys {
		if !previousSet[k] {
			diff.NewFindings = append(diff.NewFindings, k)
		}
	}

	for _, k := range last.FindingKeys {
		if !currentSet[k] {
			diff.ResolvedFindings = append(diff.ResolvedFindings, k)
		}
	}

	return diff, nil
}

func generateID(report model.Report) string {
	h := sha256.New()
	h.Write([]byte(report.Host.Hostname))
	h.Write([]byte(report.GeneratedAt.String()))
	return fmt.Sprintf("%x", h.Sum(nil))[:12]
}

func extractFindingKeys(report model.Report) []string {
	allFindings := make([]model.Finding, 0,
		len(report.DirectFindings)+len(report.HeuristicFindings)+len(report.CompromiseIndicators))
	allFindings = append(allFindings, report.DirectFindings...)
	allFindings = append(allFindings, report.HeuristicFindings...)
	allFindings = append(allFindings, report.CompromiseIndicators...)

	keys := make([]string, 0, len(allFindings))
	for _, f := range allFindings {
		keys = append(keys, f.Fingerprint())
	}
	sort.Strings(keys)
	return keys
}

func sanitizeName(name string) string {
	name = strings.ReplaceAll(name, "/", "_")
	name = strings.ReplaceAll(name, " ", "_")
	if len(name) > 40 {
		name = name[:40]
	}
	return name
}

func toSet(items []string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, item := range items {
		m[item] = true
	}
	return m
}
