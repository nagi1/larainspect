package theme

import (
	"testing"

	"github.com/nagi1/larainspect/internal/model"
)

func TestDefaultThemeNotNil(t *testing.T) {
	th := DefaultTheme()
	if th == nil {
		t.Fatal("DefaultTheme() returned nil")
	}
}

func TestSeverityStylesForAllLevels(t *testing.T) {
	th := DefaultTheme()
	severities := []model.Severity{
		model.SeverityCritical,
		model.SeverityHigh,
		model.SeverityMedium,
		model.SeverityLow,
		model.SeverityInformational,
	}
	for _, sev := range severities {
		if _, ok := th.SeverityStyles[sev]; !ok {
			t.Errorf("missing SeverityStyle for %q", sev)
		}
	}
}

func TestSeverityColor(t *testing.T) {
	th := DefaultTheme()

	// Just verify it doesn't panic and returns something for known severities
	for _, sev := range OrderedSeverities() {
		color := th.SeverityColor(sev)
		if color.Light == "" && color.Dark == "" {
			t.Errorf("SeverityColor(%q) returned empty colors", sev)
		}
	}

	// Unknown severity should return TextDim
	unknownColor := th.SeverityColor("nonexistent")
	if unknownColor != th.Colors.TextDim {
		t.Error("unknown severity should return TextDim color")
	}
}

func TestOrderedSeveritiesMatchesReportfmt(t *testing.T) {
	ordered := OrderedSeverities()
	if len(ordered) != 5 {
		t.Fatalf("OrderedSeverities() length = %d, want 5", len(ordered))
	}
	if ordered[0] != model.SeverityCritical {
		t.Errorf("first severity = %q, want critical", ordered[0])
	}
	if ordered[4] != model.SeverityInformational {
		t.Errorf("last severity = %q, want informational", ordered[4])
	}
}

func TestSeverityLabel(t *testing.T) {
	tests := []struct {
		severity model.Severity
		want     string
	}{
		{model.SeverityCritical, "Critical"},
		{model.SeverityHigh, "High"},
		{model.SeverityMedium, "Medium"},
		{model.SeverityLow, "Low"},
		{model.SeverityInformational, "Info"},
		{"custom", "custom"},
	}
	for _, tt := range tests {
		got := SeverityLabel(tt.severity)
		if got != tt.want {
			t.Errorf("SeverityLabel(%q) = %q, want %q", tt.severity, got, tt.want)
		}
	}
}
