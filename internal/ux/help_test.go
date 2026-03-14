package ux

import (
	"strings"
	"testing"
)

func TestRootHelp(t *testing.T) {
	t.Parallel()

	help := RootHelp()
	for _, want := range []string{
		Banner(),
		"Read-only Laravel VPS auditor for operators under pressure.",
		"Safety promises:",
		"larainspect audit --interactive",
	} {
		if !strings.Contains(help, want) {
			t.Fatalf("expected root help to contain %q, got %q", want, help)
		}
	}
}

func TestAuditHelp(t *testing.T) {
	t.Parallel()

	help := AuditHelp()
	for _, want := range []string{
		"Helpful modes:",
		"Accessibility:",
		"--scan-root",
		"--screen-reader",
		"Exit codes:",
	} {
		if !strings.Contains(help, want) {
			t.Fatalf("expected audit help to contain %q, got %q", want, help)
		}
	}
}
