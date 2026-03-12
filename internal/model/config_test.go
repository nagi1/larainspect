package model_test

import (
	"testing"
	"time"

	"github.com/nagi1/larainspect/internal/model"
)

func TestVerbosityValid(t *testing.T) {
	t.Parallel()

	if !model.VerbosityQuiet.Valid() || !model.VerbosityNormal.Valid() || !model.VerbosityVerbose.Valid() {
		t.Fatal("expected built-in verbosities to be valid")
	}

	if model.Verbosity("loud").Valid() {
		t.Fatal("expected invalid verbosity to be rejected")
	}
}

func TestScanScopeValid(t *testing.T) {
	t.Parallel()

	if !model.ScanScopeAuto.Valid() || !model.ScanScopeHost.Valid() || !model.ScanScopeApp.Valid() {
		t.Fatal("expected built-in scan scopes to be valid")
	}

	if model.ScanScope("site").Valid() {
		t.Fatal("expected invalid scan scope to be rejected")
	}
}

func TestColorModeValid(t *testing.T) {
	t.Parallel()

	if !model.ColorModeAuto.Valid() || !model.ColorModeAlways.Valid() || !model.ColorModeNever.Valid() {
		t.Fatal("expected built-in color modes to be valid")
	}

	if model.ColorMode("sometimes").Valid() {
		t.Fatal("expected invalid color mode to be rejected")
	}
}

func TestAuditConfigValidate(t *testing.T) {
	t.Parallel()

	valid := model.AuditConfig{
		Format:         model.OutputFormatTerminal,
		CommandTimeout: time.Second,
		MaxOutputBytes: 1024,
		WorkerLimit:    1,
		Verbosity:      model.VerbosityNormal,
		Scope:          model.ScanScopeAuto,
		ColorMode:      model.ColorModeAuto,
	}

	if err := valid.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	testCases := []model.AuditConfig{
		{Verbosity: model.VerbosityNormal, Scope: model.ScanScopeAuto, ColorMode: model.ColorModeAuto},
		{Format: "bad", Verbosity: model.VerbosityNormal, Scope: model.ScanScopeAuto, ColorMode: model.ColorModeAuto},
		{Format: model.OutputFormatTerminal, Verbosity: model.Verbosity("bad"), Scope: model.ScanScopeAuto, ColorMode: model.ColorModeAuto},
		{Format: model.OutputFormatTerminal, Verbosity: model.VerbosityNormal, Scope: model.ScanScope("bad"), ColorMode: model.ColorModeAuto},
		{Format: model.OutputFormatTerminal, Verbosity: model.VerbosityNormal, Scope: model.ScanScopeAuto, ColorMode: model.ColorMode("bad")},
		{Format: model.OutputFormatTerminal, Verbosity: model.VerbosityNormal, Scope: model.ScanScopeAuto, ColorMode: model.ColorModeAuto, Profile: model.HostProfile{OSFamily: "fedorra"}},
	}

	for _, config := range testCases {
		if err := config.Validate(); err == nil {
			t.Fatalf("expected validation error for config %+v", config)
		}
	}
}

func TestIsSupportedOSFamily(t *testing.T) {
	t.Parallel()

	for _, osFamily := range []string{"", "auto", "custom", "ubuntu", "debian", "fedora", "rhel", "centos", "rocky", "almalinux"} {
		if !model.IsSupportedOSFamily(osFamily) {
			t.Fatalf("expected %q to be supported", osFamily)
		}
	}

	if model.IsSupportedOSFamily("freebsd") {
		t.Fatal("expected unsupported os family to be rejected")
	}
}

func TestOutputFormatHelpers(t *testing.T) {
	t.Parallel()

	if got := model.NormalizeOutputFormat(" JSON "); got != model.OutputFormatJSON {
		t.Fatalf("NormalizeOutputFormat() = %q", got)
	}

	if !model.IsValidOutputFormat(model.OutputFormatTerminal) || !model.IsValidOutputFormat(model.OutputFormatJSON) {
		t.Fatal("expected built-in output formats to be valid")
	}

	if model.IsValidOutputFormat("xml") {
		t.Fatal("expected invalid format to be rejected")
	}

	if !(model.AuditConfig{Format: model.OutputFormatTerminal}).UsesTerminalOutput() {
		t.Fatal("expected terminal config to use terminal output")
	}
}

func TestAuditConfigValidateResolved(t *testing.T) {
	t.Parallel()

	if err := (model.AuditConfig{Scope: model.ScanScopeApp}).ValidateResolved(); err == nil {
		t.Fatal("expected missing app path error")
	}

	if err := (model.AuditConfig{Scope: model.ScanScopeApp, AppPath: "/var/www/shop"}).ValidateResolved(); err != nil {
		t.Fatalf("ValidateResolved() error = %v", err)
	}
}

func TestAuditConfigShouldDiscoverApplications(t *testing.T) {
	t.Parallel()

	if (model.AuditConfig{Scope: model.ScanScopeHost}).ShouldDiscoverApplications() {
		t.Fatal("expected host scope to skip app discovery")
	}

	if !(model.AuditConfig{Scope: model.ScanScopeAuto}).ShouldDiscoverApplications() {
		t.Fatal("expected auto scope to allow app discovery")
	}
}

func TestAuditConfigNormalizedScanRoots(t *testing.T) {
	t.Parallel()

	config := model.AuditConfig{
		ScanRoots: []string{" /var/www ", "/srv/../srv/apps", "/var/www", ""},
	}

	got := config.NormalizedScanRoots()
	want := []string{"/srv/apps", "/var/www"}

	if len(got) != len(want) {
		t.Fatalf("NormalizedScanRoots() length = %d, want %d (%v)", len(got), len(want), got)
	}

	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("NormalizedScanRoots()[%d] = %q, want %q (%v)", index, got[index], want[index], got)
		}
	}
}
