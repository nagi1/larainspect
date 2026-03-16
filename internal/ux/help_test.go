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
		"larainspect init",
		"larainspect populate",
		"larainspect setup",
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

func TestInitHelp(t *testing.T) {
	t.Parallel()

	help := InitHelp()
	for _, want := range []string{
		"Write a starter larainspect.yaml",
		"--path string",
		"--preset string",
	} {
		if !strings.Contains(help, want) {
			t.Fatalf("expected init help to contain %q, got %q", want, help)
		}
	}
}

func TestSetupHelp(t *testing.T) {
	t.Parallel()

	help := SetupHelp()
	for _, want := range []string{
		"Detect a likely hosting preset",
		"Supported presets:",
		"aapanel",
		"cpanel",
	} {
		if !strings.Contains(help, want) {
			t.Fatalf("expected setup help to contain %q, got %q", want, help)
		}
	}
}

func TestPopulateHelp(t *testing.T) {
	t.Parallel()

	help := PopulateHelp()
	for _, want := range []string{
		"Fill missing or empty config values",
		"--config string",
		"--interactive",
		"--preset string",
	} {
		if !strings.Contains(help, want) {
			t.Fatalf("expected populate help to contain %q, got %q", want, help)
		}
	}
}
