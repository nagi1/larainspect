package ux

import (
	"bufio"
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/nagi1/larainspect/internal/model"
)

func TestResolveAuditConfigNoInteractive(t *testing.T) {
	t.Parallel()

	config := model.AuditConfig{Interactive: false, Scope: model.ScanScopeAuto}
	got, err := Prompter{Input: strings.NewReader(""), Output: &bytes.Buffer{}}.ResolveAuditConfig(config)
	if err != nil {
		t.Fatalf("ResolveAuditConfig() error = %v", err)
	}
	if got.Scope != model.ScanScopeAuto {
		t.Fatalf("unexpected scope %q", got.Scope)
	}
}

func TestResolveAuditConfigInvalidInteractiveScope(t *testing.T) {
	t.Parallel()

	_, err := Prompter{Input: strings.NewReader("bad\n"), Output: &bytes.Buffer{}}.ResolveAuditConfig(model.AuditConfig{
		Interactive: true,
		Scope:       model.ScanScopeAuto,
	})
	if err == nil {
		t.Fatal("expected invalid scope error")
	}
}

func TestResolveAuditConfigBlankInteractiveAppPath(t *testing.T) {
	t.Parallel()

	_, err := Prompter{Input: strings.NewReader("app\n\n"), Output: &bytes.Buffer{}}.ResolveAuditConfig(model.AuditConfig{
		Interactive: true,
		Scope:       model.ScanScopeAuto,
	})
	if err == nil {
		t.Fatal("expected blank app path error")
	}
}

func TestPromptLineHandlesEOF(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	response, err := (Prompter{Input: strings.NewReader("value"), Output: &output}).promptLine(bufio.NewReader(strings.NewReader("value")), "Label: ")
	if err != nil && err != io.EOF {
		t.Fatalf("promptLine() unexpected error = %v", err)
	}
	if response != "value" {
		t.Fatalf("expected value, got %q", response)
	}
	if !strings.Contains(output.String(), "Label: ") {
		t.Fatalf("expected label output, got %q", output.String())
	}
}

func TestResolveAuditConfigKeepsDefaultScopeOnBlankInput(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	config, err := Prompter{Input: strings.NewReader("\n"), Output: &output}.ResolveAuditConfig(model.AuditConfig{
		Interactive: true,
		Scope:       model.ScanScopeAuto,
	})
	if err != nil {
		t.Fatalf("ResolveAuditConfig() error = %v", err)
	}
	if config.Scope != model.ScanScopeAuto {
		t.Fatalf("expected auto scope, got %q", config.Scope)
	}
}

func TestResolveAuditConfigAppScopeWithoutPromptingForScope(t *testing.T) {
	t.Parallel()

	config, err := Prompter{Input: strings.NewReader("/var/www/shop\n"), Output: &bytes.Buffer{}}.ResolveAuditConfig(model.AuditConfig{
		Interactive: true,
		Scope:       model.ScanScopeApp,
	})
	if err != nil {
		t.Fatalf("ResolveAuditConfig() error = %v", err)
	}
	if config.AppPath != "/var/www/shop" {
		t.Fatalf("expected app path to be captured, got %q", config.AppPath)
	}
}
