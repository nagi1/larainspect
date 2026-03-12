package ux

import (
	"strings"
	"testing"

	"github.com/nagi/larainspect/internal/model"
)

func TestOnboardingModes(t *testing.T) {
	t.Parallel()

	if got := Onboarding(model.AuditConfig{Verbosity: model.VerbosityQuiet}); got != "" {
		t.Fatalf("expected quiet onboarding to be empty, got %q", got)
	}

	verbose := Onboarding(model.AuditConfig{
		Format:       "terminal",
		Verbosity:    model.VerbosityVerbose,
		Scope:        model.ScanScopeApp,
		AppPath:      "/var/www/shop",
		Interactive:  true,
		ColorMode:    model.ColorModeNever,
		ScreenReader: true,
		WorkerLimit:  2,
	})

	for _, want := range []string{
		"Starting read-only audit",
		"Scope: app-focused run at /var/www/shop",
		"Interactivity: enabled",
		"Color preference: never",
		"Screen-reader mode: enabled",
	} {
		if !strings.Contains(verbose, want) {
			t.Fatalf("expected onboarding to contain %q, got %q", want, verbose)
		}
	}

	normal := Onboarding(model.AuditConfig{
		Format:      "terminal",
		Verbosity:   model.VerbosityNormal,
		Scope:       model.ScanScopeHost,
		ColorMode:   model.ColorModeAuto,
		WorkerLimit: 1,
	})
	if !strings.Contains(normal, "Tip: use --format json") {
		t.Fatalf("expected normal onboarding tip, got %q", normal)
	}

	auto := Onboarding(model.AuditConfig{
		Format:      "terminal",
		Verbosity:   model.VerbosityNormal,
		Scope:       model.ScanScopeAuto,
		ColorMode:   model.ColorModeAuto,
		WorkerLimit: 1,
	})
	if !strings.Contains(auto, "Scope: automatic scope selection") {
		t.Fatalf("expected auto scope description, got %q", auto)
	}
}

func TestFooterModes(t *testing.T) {
	t.Parallel()

	if got := Footer(model.Report{}, model.AuditConfig{Verbosity: model.VerbosityQuiet}); got != "" {
		t.Fatalf("expected quiet footer to be empty, got %q", got)
	}

	clean := Footer(model.Report{}, model.AuditConfig{Verbosity: model.VerbosityNormal})
	if !strings.Contains(clean, "No Laravel-specific checks are registered yet") {
		t.Fatalf("expected clean footer guidance, got %q", clean)
	}

	report := model.Report{Summary: model.Summary{TotalFindings: 1}}
	findingFooter := Footer(report, model.AuditConfig{Verbosity: model.VerbosityVerbose, Scope: model.ScanScopeAuto})
	if !strings.Contains(findingFooter, "Review direct findings first") {
		t.Fatalf("expected finding footer guidance, got %q", findingFooter)
	}
	if !strings.Contains(findingFooter, "--scope app --app-path") {
		t.Fatalf("expected app scope tip, got %q", findingFooter)
	}

	screenReaderFooter := Footer(report, model.AuditConfig{Verbosity: model.VerbosityNormal, Scope: model.ScanScopeAuto, ScreenReader: true})
	if strings.Contains(screenReaderFooter, "--scope app --app-path") {
		t.Fatalf("expected screen-reader footer to omit extra tip, got %q", screenReaderFooter)
	}
}

func TestEnabledDisabledAndDescribeScopeFallback(t *testing.T) {
	t.Parallel()

	if got := enabledDisabled(false); got != "disabled" {
		t.Fatalf("enabledDisabled(false) = %q", got)
	}

	if got := describeScope(model.AuditConfig{Scope: model.ScanScopeApp}); got != "app-focused run" {
		t.Fatalf("describeScope(app without path) = %q", got)
	}
}
