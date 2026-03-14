package discovery

import (
	"regexp"
	"testing"

	"github.com/nagi1/larainspect/internal/model"
)

func TestLineContainsAny(t *testing.T) {
	t.Parallel()

	if !lineContainsAny("eval($code)", []string{"$code"}) {
		t.Error("expected true")
	}
	if lineContainsAny("safe line", []string{"evil"}) {
		t.Error("expected false")
	}
	if lineContainsAny("any line", nil) {
		t.Error("expected false for nil candidates")
	}
}

func TestAppendSourceMatchIfMatchesRegex(t *testing.T) {
	t.Parallel()

	content := "line1\nfoo_bar_baz\nline3"
	pattern := compilePattern(`foo_bar`)

	matches := appendSourceMatchIfMatchesRegex(nil, "test.php", content, "test.id", "detail", pattern)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].Line != 2 {
		t.Errorf("expected line 2, got %d", matches[0].Line)
	}

	matches = appendSourceMatchIfMatchesRegex(nil, "test.php", content, "test.id", "detail", compilePattern(`nonexistent`))
	if len(matches) != 0 {
		t.Fatal("expected 0 matches")
	}
}

func TestParseDirectiveLine(t *testing.T) {
	t.Parallel()

	key, value, ok := parseDirectiveLine("listen = 80")
	if !ok || key != "listen" || value != "80" {
		t.Errorf("got key=%q value=%q ok=%v", key, value, ok)
	}

	_, _, ok = parseDirectiveLine("no-separator-line")
	if ok {
		t.Error("expected ok=false for missing separator")
	}
}

func TestTrimINICommentLine(t *testing.T) {
	t.Parallel()

	if got := trimINICommentLine("  ; comment  "); got != "" {
		t.Errorf("expected empty for ;-comment, got %q", got)
	}
	if got := trimINICommentLine("  # comment  "); got != "" {
		t.Errorf("expected empty for #-comment, got %q", got)
	}
	if got := trimINICommentLine("  "); got != "" {
		t.Errorf("expected empty for whitespace, got %q", got)
	}
	if got := trimINICommentLine("  key=value  "); got != "key=value" {
		t.Errorf("expected directive, got %q", got)
	}
}

func TestBuildUnknownID(t *testing.T) {
	t.Parallel()

	id := buildUnknownID("nginx.config", "Read failed", "/etc/nginx/nginx.conf")
	if id == "" {
		t.Fatal("expected non-empty ID")
	}
}

func TestContainsRuleIDAtRelativePath(t *testing.T) {
	t.Parallel()

	matches := []model.SourceMatch{
		{RuleID: "rule.a", RelativePath: "routes/web.php"},
	}

	if !containsRuleIDAtRelativePath(matches, "rule.a", "routes/web.php") {
		t.Error("expected true")
	}
	if containsRuleIDAtRelativePath(matches, "rule.b", "routes/web.php") {
		t.Error("expected false for wrong rule")
	}
	if containsRuleIDAtRelativePath(nil, "rule.a", "routes/web.php") {
		t.Error("expected false for nil matches")
	}
}

func TestAppendSourceMatchIfMatchesAnyRegex(t *testing.T) {
	t.Parallel()

	content := "line1\neval($code)\nline3"
	p1 := compilePattern(`nonexistent`)
	p2 := compilePattern(`eval\(`)

	matches := appendSourceMatchIfMatchesAnyRegex(nil, "test.php", content, "test.id", "eval found", []*regexp.Regexp{p1, p2})
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].Line != 2 {
		t.Errorf("expected line 2, got %d", matches[0].Line)
	}

	matches = appendSourceMatchIfMatchesAnyRegex(nil, "test.php", content, "test.id", "detail", []*regexp.Regexp{compilePattern(`no_match`)})
	if len(matches) != 0 {
		t.Fatal("expected 0 matches when no patterns match")
	}
}

func TestAppendSourceMatchIfContainsAny(t *testing.T) {
	t.Parallel()

	content := "something with eval and exec"

	matches := appendSourceMatchIfContainsAny(nil, "test.php", content, "test.id", "found", []string{"nothere", "eval"})
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}

	matches = appendSourceMatchIfContainsAny(nil, "test.php", content, "test.id", "found", []string{"missing1", "missing2"})
	if len(matches) != 0 {
		t.Fatal("expected 0 matches when nothing found")
	}
}

func TestAppendSourceMatchIfLineMatchesRegex(t *testing.T) {
	t.Parallel()

	content := "safe line\neval($code)"
	pattern := compilePattern(`eval\(`)

	matches := appendSourceMatchIfLineMatchesRegex(nil, "test.php", content, "test.id", "eval found", pattern)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].Line != 2 {
		t.Errorf("expected line 2, got %d", matches[0].Line)
	}

	matches = appendSourceMatchIfLineMatchesRegex(nil, "test.php", content, "test.id", "detail", compilePattern(`nonexistent`))
	if len(matches) != 0 {
		t.Fatal("expected 0 matches")
	}
}
