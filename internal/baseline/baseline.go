package baseline

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/nagi1/larainspect/internal/model"
)

// Entry represents a single baselined finding.
type Entry struct {
	Fingerprint string `json:"fingerprint"`
	ID          string `json:"id"`
	CheckID     string `json:"check_id"`
	Class       string `json:"class"`
	Title       string `json:"title"`
	Severity    string `json:"severity"`
}

// Baseline is the on-disk format for suppressed findings.
type Baseline struct {
	Version   string    `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Entries   []Entry   `json:"entries"`

	// In-memory lookup set, built on load.
	fingerprints map[string]bool
}

// Load reads a baseline file from disk. Returns nil (not error) if
// the file does not exist, so callers can treat "no baseline" as "no
// suppression" without extra checks.
func Load(path string) (*Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading baseline %s: %w", path, err)
	}

	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("parsing baseline %s: %w", path, err)
	}

	b.fingerprints = make(map[string]bool, len(b.Entries))
	for _, e := range b.Entries {
		b.fingerprints[e.Fingerprint] = true
	}

	return &b, nil
}

// Save writes a baseline file from the given findings.
func Save(path string, findings []model.Finding) error {
	entries := make([]Entry, 0, len(findings))
	for _, f := range findings {
		entries = append(entries, Entry{
			Fingerprint: f.Fingerprint(),
			ID:          f.ID,
			CheckID:     f.CheckID,
			Class:       string(f.Class),
			Title:       f.Title,
			Severity:    string(f.Severity),
		})
	}

	b := Baseline{
		Version:   "1.0",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
		Entries:   entries,
	}

	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding baseline: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("writing baseline to %s: %w", path, err)
	}

	return nil
}

// IsBaselined returns true if the finding is suppressed by this baseline.
func (b *Baseline) IsBaselined(f model.Finding) bool {
	if b == nil || b.fingerprints == nil {
		return false
	}
	return b.fingerprints[f.Fingerprint()]
}

// Filter removes baselined findings from the list and returns the active
// findings and the count of suppressed entries. Unknowns are never
// suppressed to preserve visibility.
func (b *Baseline) Filter(findings []model.Finding) (active []model.Finding, suppressed int) {
	if b == nil {
		return findings, 0
	}

	active = make([]model.Finding, 0, len(findings))
	for _, f := range findings {
		if b.IsBaselined(f) {
			suppressed++
		} else {
			active = append(active, f)
		}
	}
	return active, suppressed
}
