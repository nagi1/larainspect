package ux

import (
	"bufio"
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

func TestResolveIdentityAnswersPromptsForMissingValues(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	answers, err := Prompter{
		Input:  strings.NewReader("deploy-user\nruntime-user\nruntime-group\nweb-user\nweb-group\n"),
		Output: &output,
	}.ResolveIdentityAnswers(IdentityAnswers{})
	if err != nil {
		t.Fatalf("ResolveIdentityAnswers() error = %v", err)
	}

	if len(answers.DeployUsers) != 1 || answers.DeployUsers[0] != "deploy-user" {
		t.Fatalf("unexpected deploy users %+v", answers.DeployUsers)
	}
	if len(answers.RuntimeUsers) != 1 || answers.RuntimeUsers[0] != "runtime-user" {
		t.Fatalf("unexpected runtime users %+v", answers.RuntimeUsers)
	}
	if len(answers.RuntimeGroups) != 1 || answers.RuntimeGroups[0] != "runtime-group" {
		t.Fatalf("unexpected runtime groups %+v", answers.RuntimeGroups)
	}
	if len(answers.WebUsers) != 1 || answers.WebUsers[0] != "web-user" {
		t.Fatalf("unexpected web users %+v", answers.WebUsers)
	}
	if len(answers.WebGroups) != 1 || answers.WebGroups[0] != "web-group" {
		t.Fatalf("unexpected web groups %+v", answers.WebGroups)
	}
	if !strings.Contains(output.String(), "Could not confidently detect all deploy, runtime, and web identities") {
		t.Fatalf("expected guidance message, got %q", output.String())
	}
}

func TestResolveIdentityAnswersKeepsDefaultsForKnownValues(t *testing.T) {
	t.Parallel()

	answers, err := Prompter{
		Input:  strings.NewReader("runtime-group\nweb-group\n"),
		Output: &bytes.Buffer{},
	}.ResolveIdentityAnswers(IdentityAnswers{
		DeployUsers:  []string{"forge"},
		RuntimeUsers: []string{"forge"},
		WebUsers:     []string{"www-data"},
	})
	if err != nil {
		t.Fatalf("ResolveIdentityAnswers() error = %v", err)
	}

	if len(answers.DeployUsers) != 1 || answers.DeployUsers[0] != "forge" {
		t.Fatalf("unexpected deploy users %+v", answers.DeployUsers)
	}
	if len(answers.RuntimeUsers) != 1 || answers.RuntimeUsers[0] != "forge" {
		t.Fatalf("unexpected runtime users %+v", answers.RuntimeUsers)
	}
	if len(answers.RuntimeGroups) != 1 || answers.RuntimeGroups[0] != "runtime-group" {
		t.Fatalf("unexpected runtime groups %+v", answers.RuntimeGroups)
	}
	if len(answers.WebUsers) != 1 || answers.WebUsers[0] != "www-data" {
		t.Fatalf("unexpected web users %+v", answers.WebUsers)
	}
	if len(answers.WebGroups) != 1 || answers.WebGroups[0] != "web-group" {
		t.Fatalf("unexpected web groups %+v", answers.WebGroups)
	}
}

func TestSplitIdentityListDeduplicatesCaseInsensitiveValues(t *testing.T) {
	t.Parallel()

	values := splitIdentityList(" forge,Forge, www-data , , WWW-DATA ")
	if len(values) != 2 {
		t.Fatalf("expected 2 values, got %+v", values)
	}
	if values[0] != "forge" || values[1] != "www-data" {
		t.Fatalf("unexpected values %+v", values)
	}
}

func TestResolveSetupAnswersRejectsInvalidScope(t *testing.T) {
	t.Parallel()

	_, err := Prompter{Input: strings.NewReader("vps\nauto\ninvalid\n"), Output: &bytes.Buffer{}}.ResolveSetupAnswers(SetupAnswers{
		Preset:   "vps",
		OSFamily: "auto",
		Scope:    model.ScanScopeAuto,
	})
	if err == nil {
		t.Fatal("expected invalid scope error")
	}
}

func TestPromptIdentityListAllowsBlankInput(t *testing.T) {
	t.Parallel()

	values, err := Prompter{Input: strings.NewReader("\n"), Output: &bytes.Buffer{}}.promptIdentityList(bufio.NewReader(strings.NewReader("\n")), "Deploy users")
	if err != nil {
		t.Fatalf("promptIdentityList() error = %v", err)
	}
	if values != nil {
		t.Fatalf("expected nil values, got %+v", values)
	}
}
