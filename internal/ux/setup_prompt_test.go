package ux

import (
	"bytes"
	"strings"
	"testing"

	"github.com/nagi1/larainspect/internal/model"
)

func TestResolveSetupAnswersUsesDefaults(t *testing.T) {
	t.Parallel()

	answers, err := Prompter{Input: strings.NewReader("\n\n\n"), Output: &bytes.Buffer{}}.ResolveSetupAnswers(SetupAnswers{
		Preset:   "vps",
		OSFamily: "auto",
		Scope:    model.ScanScopeAuto,
	})
	if err != nil {
		t.Fatalf("ResolveSetupAnswers() error = %v", err)
	}
	if answers.Preset != "vps" || answers.OSFamily != "auto" || answers.Scope != model.ScanScopeAuto {
		t.Fatalf("unexpected answers %+v", answers)
	}
}

func TestResolveSetupAnswersRequiresAppPathForAppScope(t *testing.T) {
	t.Parallel()

	_, err := Prompter{Input: strings.NewReader("vps\nauto\napp\n\n"), Output: &bytes.Buffer{}}.ResolveSetupAnswers(SetupAnswers{
		Preset:   "vps",
		OSFamily: "auto",
		Scope:    model.ScanScopeAuto,
	})
	if err == nil {
		t.Fatal("expected missing app path error")
	}
}
