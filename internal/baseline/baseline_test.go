package baseline_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nagi1/larainspect/internal/baseline"
	"github.com/nagi1/larainspect/internal/model"
)

func testFindings() []model.Finding {
	return []model.Finding{
		{
			ID:          "f1",
			CheckID:     "CHECK_A",
			Class:       model.FindingClassDirect,
			Severity:    model.SeverityHigh,
			Confidence:  model.ConfidenceConfirmed,
			Title:       "Debug enabled",
			Why:         "Leaks info",
			Remediation: "Disable it",
			Evidence:    []model.Evidence{{Label: "env", Detail: "APP_DEBUG=true"}},
			Affected:    []model.Target{{Type: "file", Path: "/app/.env"}},
		},
		{
			ID:          "f2",
			CheckID:     "CHECK_B",
			Class:       model.FindingClassHeuristic,
			Severity:    model.SeverityMedium,
			Confidence:  model.ConfidenceProbable,
			Title:       "Session config",
			Why:         "Insecure cookies",
			Remediation: "Fix it",
			Evidence:    []model.Evidence{{Label: "config", Detail: "secure=false"}},
		},
	}
}

func TestSaveAndLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")

	findings := testFindings()
	if err := baseline.Save(path, findings); err != nil {
		t.Fatalf("Save: %v", err)
	}

	b, err := baseline.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if b == nil {
		t.Fatal("Load returned nil baseline")
	}

	if len(b.Entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(b.Entries))
	}

	// Verify each original finding is baselined.
	for _, f := range findings {
		if !b.IsBaselined(f) {
			t.Errorf("expected finding %q to be baselined", f.ID)
		}
	}
}

func TestLoadNonexistent(t *testing.T) {
	b, err := baseline.Load("/nonexistent/path/baseline.json")
	if err != nil {
		t.Fatalf("Load should not error for missing file: %v", err)
	}
	if b != nil {
		t.Fatal("Load should return nil for missing file")
	}
}

func TestFilterSuppresses(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")
	findings := testFindings()

	if err := baseline.Save(path, findings); err != nil {
		t.Fatalf("Save: %v", err)
	}

	b, err := baseline.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	active, suppressed := b.Filter(findings)
	if suppressed != 2 {
		t.Errorf("expected 2 suppressed, got %d", suppressed)
	}
	if len(active) != 0 {
		t.Errorf("expected 0 active, got %d", len(active))
	}
}

func TestFilterNewFindingsPassThrough(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")

	// Save baseline with only the first finding.
	if err := baseline.Save(path, testFindings()[:1]); err != nil {
		t.Fatalf("Save: %v", err)
	}

	b, err := baseline.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Filter with both findings — second one should pass through.
	active, suppressed := b.Filter(testFindings())
	if suppressed != 1 {
		t.Errorf("expected 1 suppressed, got %d", suppressed)
	}
	if len(active) != 1 {
		t.Errorf("expected 1 active, got %d", len(active))
	}
}

func TestNilBaselinePassesAll(t *testing.T) {
	var b *baseline.Baseline
	active, suppressed := b.Filter(testFindings())
	if suppressed != 0 {
		t.Error("nil baseline should suppress nothing")
	}
	if len(active) != 2 {
		t.Errorf("expected 2 active, got %d", len(active))
	}
}

func TestBaselineFilePermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")

	if err := baseline.Save(path, testFindings()); err != nil {
		t.Fatalf("Save: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}

	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Errorf("expected permissions 0600, got %o", perm)
	}
}

func TestLoadCorruptJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")

	if err := os.WriteFile(path, []byte("{invalid json"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := baseline.Load(path)
	if err == nil {
		t.Fatal("expected error for corrupt JSON")
	}
}

func TestLoadUnreadableFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")

	if err := os.WriteFile(path, []byte("{}"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Chmod(path, 0000); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0600) })

	_, err := baseline.Load(path)
	if err == nil {
		t.Fatal("expected error for unreadable file")
	}
}

func TestIsBaselinedOnZeroBaseline(t *testing.T) {
	b := &baseline.Baseline{}
	finding := testFindings()[0]

	if b.IsBaselined(finding) {
		t.Fatal("zero value Baseline should not match any finding")
	}
}

func TestSaveRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")
	findings := testFindings()

	if err := baseline.Save(path, findings); err != nil {
		t.Fatalf("Save: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	if len(data) == 0 {
		t.Fatal("saved file should not be empty")
	}

	b, err := baseline.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if b.Version != "1.0" {
		t.Fatalf("expected version 1.0, got %q", b.Version)
	}
	if len(b.Entries) != len(findings) {
		t.Fatalf("expected %d entries, got %d", len(findings), len(b.Entries))
	}

	// Every original finding should still be baselined.
	for _, f := range findings {
		if !b.IsBaselined(f) {
			t.Errorf("finding %q not baselined after round-trip", f.ID)
		}
	}
}

func TestSaveEmptyFindings(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")

	if err := baseline.Save(path, nil); err != nil {
		t.Fatalf("Save: %v", err)
	}

	b, err := baseline.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(b.Entries) != 0 {
		t.Fatalf("expected 0 entries, got %d", len(b.Entries))
	}
}
