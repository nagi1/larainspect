package store

import (
	"testing"
	"time"

	"github.com/nagi1/larainspect/internal/model"
)

func TestGenerateIDDeterministic(t *testing.T) {
	t.Parallel()

	report := model.Report{
		Host:        model.Host{Hostname: "web-01"},
		GeneratedAt: time.Date(2025, 6, 15, 10, 0, 0, 0, time.UTC),
	}

	id1 := generateID(report)
	id2 := generateID(report)

	if id1 != id2 {
		t.Fatalf("expected deterministic IDs, got %q and %q", id1, id2)
	}
	if len(id1) != 12 {
		t.Fatalf("expected 12-char ID, got %d chars: %q", len(id1), id1)
	}

	different := model.Report{
		Host:        model.Host{Hostname: "web-02"},
		GeneratedAt: time.Date(2025, 6, 15, 10, 0, 0, 0, time.UTC),
	}
	if generateID(different) == id1 {
		t.Fatal("expected different hosts to produce different IDs")
	}
}

func TestSanitizeNameTransformations(t *testing.T) {
	t.Parallel()

	cases := []struct {
		input string
		want  string
	}{
		{"simple", "simple"},
		{"my/host/name", "my_host_name"},
		{"host name", "host_name"},
		{"a/b c", "a_b_c"},
		{"", ""},
		{
			"this-is-a-very-long-hostname-that-exceeds-forty-characters-limit",
			"this-is-a-very-long-hostname-that-exceed",
		},
	}

	for _, tc := range cases {
		got := sanitizeName(tc.input)
		if got != tc.want {
			t.Errorf("sanitizeName(%q) = %q, want %q", tc.input, got, tc.want)
		}
		if len(got) > 40 {
			t.Errorf("sanitizeName(%q) length %d exceeds 40", tc.input, len(got))
		}
	}
}

func TestToSetConversion(t *testing.T) {
	t.Parallel()

	m := toSet([]string{"a", "b", "c"})
	if len(m) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(m))
	}
	for _, key := range []string{"a", "b", "c"} {
		if !m[key] {
			t.Errorf("expected key %q in set", key)
		}
	}

	empty := toSet(nil)
	if len(empty) != 0 {
		t.Fatalf("expected empty set, got %d entries", len(empty))
	}
}

func TestExtractFindingKeysAggregatesAllTypes(t *testing.T) {
	t.Parallel()

	report := model.Report{
		DirectFindings: []model.Finding{
			{ID: "f1", CheckID: "a", Class: model.FindingClassDirect,
				Severity: model.SeverityHigh, Confidence: model.ConfidenceConfirmed, Title: "Direct"},
		},
		HeuristicFindings: []model.Finding{
			{ID: "f2", CheckID: "b", Class: model.FindingClassHeuristic,
				Severity: model.SeverityMedium, Confidence: model.ConfidenceProbable, Title: "Heuristic"},
		},
		CompromiseIndicators: []model.Finding{
			{ID: "f3", CheckID: "c", Class: model.FindingClassCompromiseIndicator,
				Severity: model.SeverityCritical, Confidence: model.ConfidenceConfirmed, Title: "Compromise"},
		},
	}

	keys := extractFindingKeys(report)
	if len(keys) != 3 {
		t.Fatalf("expected 3 keys, got %d", len(keys))
	}

	// Keys should be sorted.
	for i := 1; i < len(keys); i++ {
		if keys[i] < keys[i-1] {
			t.Fatalf("keys not sorted: %v", keys)
		}
	}
}

func TestExtractFindingKeysEmpty(t *testing.T) {
	t.Parallel()

	keys := extractFindingKeys(model.Report{})
	if len(keys) != 0 {
		t.Fatalf("expected 0 keys, got %d", len(keys))
	}
}
