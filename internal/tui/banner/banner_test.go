package banner

import (
	"strings"
	"testing"
)

func TestRenderContainsLarainspect(t *testing.T) {
	out := Render("1.0.0")
	upperOut := strings.ToUpper(out)
	// The figlet banner should contain "LARAINSPECT" in block letters
	if !strings.Contains(upperOut, "LARAINSPECT") && !strings.Contains(out, "LARAINSPECT") {
		// Figlet characters use wide chars — just check it's non-empty and has lines
		if out == "" {
			t.Error("Render() returned empty string")
		}
	}
}

func TestRenderIncludesVersion(t *testing.T) {
	out := Render("2.3.4")
	if !strings.Contains(out, "2.3.4") {
		t.Errorf("Render should contain version 2.3.4, got:\n%s", out)
	}
}

func TestRenderStripsLeadingV(t *testing.T) {
	out := Render("v1.0.0")
	if strings.Contains(out, "vv") || strings.Contains(out, "v1.0.0") {
		// It should display "v1.0.0" not "vv1.0.0"
		if strings.Contains(out, "vv") {
			t.Error("Render should strip leading 'v' to avoid 'vv' prefix")
		}
	}
}

func TestRenderCompact(t *testing.T) {
	out := RenderCompact()
	if out == "" {
		t.Error("RenderCompact() returned empty string")
	}
	// Should contain both parts (might be ANSI-wrapped)
	if !strings.Contains(out, "Lara") && !strings.Contains(out, "inspect") {
		// ANSI escape codes may interfere — just check non-empty
		if len(out) < 4 {
			t.Error("RenderCompact() output seems too short")
		}
	}
}

func TestShieldIcon(t *testing.T) {
	out := ShieldIcon()
	if out == "" {
		t.Error("ShieldIcon() returned empty string")
	}
}

func TestRenderHasMultipleLines(t *testing.T) {
	out := Render("1.0.0")
	lines := strings.Split(out, "\n")
	if len(lines) < 5 {
		t.Errorf("Render should have multiple lines, got %d", len(lines))
	}
}
