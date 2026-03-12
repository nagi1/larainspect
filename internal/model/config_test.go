package model_test

import (
	"testing"
	"time"

	"github.com/nagi/larainspect/internal/model"
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
		Format:         "terminal",
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
		{Format: "terminal", Verbosity: model.Verbosity("bad"), Scope: model.ScanScopeAuto, ColorMode: model.ColorModeAuto},
		{Format: "terminal", Verbosity: model.VerbosityNormal, Scope: model.ScanScope("bad"), ColorMode: model.ColorModeAuto},
		{Format: "terminal", Verbosity: model.VerbosityNormal, Scope: model.ScanScopeAuto, ColorMode: model.ColorMode("bad")},
	}

	for _, config := range testCases {
		if err := config.Validate(); err == nil {
			t.Fatalf("expected validation error for config %+v", config)
		}
	}
}
