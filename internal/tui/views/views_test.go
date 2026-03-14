package views

import (
	"testing"

	"github.com/nagi1/larainspect/internal/model"
	"github.com/nagi1/larainspect/internal/tui/theme"
)

func testTheme() *theme.Theme {
	return theme.DefaultTheme()
}

func TestSortColumnStringSeverity(t *testing.T) {
	if s := SortBySeverity.String(); s != "Severity" {
		t.Errorf("SortBySeverity.String() = %q, want %q", s, "Severity")
	}
}

func TestSortColumnStringClass(t *testing.T) {
	if s := SortByClass.String(); s != "Class" {
		t.Errorf("SortByClass.String() = %q, want %q", s, "Class")
	}
}

func TestSortColumnStringCheckID(t *testing.T) {
	if s := SortByCheckID.String(); s != "Check ID" {
		t.Errorf("SortByCheckID.String() = %q, want %q", s, "Check ID")
	}
}

func TestSortColumnStringUnknown(t *testing.T) {
	if s := SortColumn(99).String(); s != "Unknown" {
		t.Errorf("SortColumn(99).String() = %q, want %q", s, "Unknown")
	}
}

func TestTruncateShort(t *testing.T) {
	if s := truncate("hi", 10); s != "hi" {
		t.Errorf("truncate short = %q, want %q", s, "hi")
	}
}

func TestTruncateExact(t *testing.T) {
	if s := truncate("hello", 5); s != "hello" {
		t.Errorf("truncate exact = %q, want %q", s, "hello")
	}
}

func TestTruncateLong(t *testing.T) {
	if s := truncate("hello world", 8); s != "hello .." {
		t.Errorf("truncate long = %q, want %q", s, "hello ..")
	}
}

func TestTruncateTiny(t *testing.T) {
	if s := truncate("hello", 2); s != "he" {
		t.Errorf("truncate tiny = %q, want %q", s, "he")
	}
}

func TestClassLabelDirect(t *testing.T) {
	if s := classLabel(model.FindingClassDirect); s != "Direct" {
		t.Errorf("classLabel(Direct) = %q", s)
	}
}

func TestClassLabelHeuristic(t *testing.T) {
	if s := classLabel(model.FindingClassHeuristic); s != "Heuristic" {
		t.Errorf("classLabel(Heuristic) = %q", s)
	}
}

func TestClassLabelIndicator(t *testing.T) {
	if s := classLabel(model.FindingClassCompromiseIndicator); s != "Indicator" {
		t.Errorf("classLabel(Indicator) = %q", s)
	}
}

func TestClassLabelUnknown(t *testing.T) {
	if s := classLabel("custom"); s != "custom" {
		t.Errorf("classLabel(custom) = %q, want %q", s, "custom")
	}
}

func TestInterleaveEmpty(t *testing.T) {
	if result := interleave(nil, ","); result != nil {
		t.Errorf("interleave(nil) = %v, want nil", result)
	}
}

func TestInterleaveSingle(t *testing.T) {
	result := interleave([]string{"a"}, ",")
	if len(result) != 1 || result[0] != "a" {
		t.Errorf("interleave([a]) = %v, want [a]", result)
	}
}

func TestInterleaveMultiple(t *testing.T) {
	result := interleave([]string{"a", "b", "c"}, "|")
	want := []string{"a", "|", "b", "|", "c"}
	if len(result) != len(want) {
		t.Fatalf("interleave length = %d, want %d", len(result), len(want))
	}
	for i, value := range result {
		if value != want[i] {
			t.Errorf("interleave[%d] = %q, want %q", i, value, want[i])
		}
	}
}

func TestPanelNameTable(t *testing.T) {
	if s := panelName(0); s != "Findings" {
		t.Errorf("panelName(0) = %q, want %q", s, "Findings")
	}
}

func TestPanelNameDetail(t *testing.T) {
	if s := panelName(1); s != "Detail" {
		t.Errorf("panelName(1) = %q, want %q", s, "Detail")
	}
}
