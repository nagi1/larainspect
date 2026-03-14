package cli

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/nagi1/larainspect/internal/controls"
)

func TestControlsCommandTextFormat(t *testing.T) {
	t.Parallel()
	app := App{stdout: io.Discard, stderr: io.Discard}
	cmd := app.newControlsCommand()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("controls text failed: %v", err)
	}
	if !strings.Contains(buf.String(), "control map") {
		t.Fatalf("expected header, got %q", buf.String()[:min(100, len(buf.String()))])
	}
}

func TestControlsCommandJSONFormat(t *testing.T) {
	t.Parallel()
	app := App{stdout: io.Discard, stderr: io.Discard}
	cmd := app.newControlsCommand()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"--format", "json"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("controls json failed: %v", err)
	}
	if !strings.Contains(buf.String(), "[") {
		t.Fatalf("expected JSON array, got %q", buf.String()[:min(50, len(buf.String()))])
	}
}

func TestControlsCommandBadFormat(t *testing.T) {
	t.Parallel()
	app := App{stdout: io.Discard, stderr: io.Discard}
	cmd := app.newControlsCommand()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"--format", "xml"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for unsupported format")
	}
}

func TestControlsCommandBadStatus(t *testing.T) {
	t.Parallel()
	app := App{stdout: io.Discard, stderr: io.Discard}
	cmd := app.newControlsCommand()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"--status", "invalid"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for invalid status")
	}
}

func TestControlsCommandStatusFilter(t *testing.T) {
	t.Parallel()
	app := App{stdout: io.Discard, stderr: io.Discard}
	cmd := app.newControlsCommand()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"--status", "implemented"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("controls status filter failed: %v", err)
	}
}

func TestControlsCommandEmptyFilter(t *testing.T) {
	t.Parallel()
	app := App{stdout: io.Discard, stderr: io.Discard}
	cmd := app.newControlsCommand()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"--check-id", "nonexistent-check"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("controls filter failed: %v", err)
	}
	if !strings.Contains(buf.String(), "No controls matched") {
		t.Fatalf("expected empty filter message, got %q", buf.String())
	}
}

func TestControlsCommandHelp(t *testing.T) {
	t.Parallel()
	app := App{stdout: io.Discard, stderr: io.Discard}
	cmd := app.newControlsCommand()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"--help"})
	_ = cmd.Execute()
	if buf.Len() == 0 {
		t.Fatal("expected help output")
	}
}

func TestRenderControlsTextWithAllFields(t *testing.T) {
	t.Parallel()
	controlsList := []controls.Control{
		{
			ID:               "C-TEST-1",
			Name:             "Test Control",
			Status:           controls.StatusImplemented,
			SourceCategories: []string{"cat1"},
			Sources:          []controls.Source{{Title: "src", URL: "https://example.com"}},
			Description:      "desc",
			EvidenceType:     controls.EvidenceHostPath,
			CheckIDs:         []string{"check-1"},
			MissingWork:      "some missing work",
		},
		{
			ID:               "C-TEST-2",
			Name:             "Out Of Scope Control",
			Status:           controls.StatusOutOfScope,
			SourceCategories: []string{"cat2"},
			Description:      "desc2",
			EvidenceType:     controls.EvidenceOutOfScope,
			OutOfScopeReason: "not applicable",
		},
	}

	var buf bytes.Buffer
	if err := renderControlsText(&buf, controlsList); err != nil {
		t.Fatal(err)
	}

	output := buf.String()
	for _, want := range []string{"C-TEST-1", "C-TEST-2", "Checks: check-1", "Checks: none", "Missing Work:", "Out Of Scope:"} {
		if !strings.Contains(output, want) {
			t.Errorf("expected %q in output, got %q", want, output)
		}
	}
}

func TestPrintControlsHelp(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	printControlsHelp(&buf)
	if buf.Len() == 0 {
		t.Fatal("expected help output")
	}
}

func TestControlsCommandFlagError(t *testing.T) {
	t.Parallel()
	app := App{stdout: io.Discard, stderr: io.Discard}
	cmd := app.newControlsCommand()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"--bogus-flag"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for unknown flag")
	}
}

type limitWriter struct {
	max int
	n   int
}

func (w *limitWriter) Write(p []byte) (int, error) {
	w.n++
	if w.n > w.max {
		return 0, errors.New("limit reached")
	}
	return len(p), nil
}

func TestRenderControlsTextWriteErrors(t *testing.T) {
	t.Parallel()
	sample := []controls.Control{
		{
			ID: "C1", Name: "First", Status: controls.StatusImplemented,
			SourceCategories: []string{"cat"}, Sources: []controls.Source{{Title: "t", URL: "u"}},
			Description: "d", EvidenceType: controls.EvidenceHostPath,
			CheckIDs: []string{"chk"}, MissingWork: "work",
		},
		{
			ID: "C2", Name: "No Checks", Status: controls.StatusOutOfScope,
			SourceCategories: []string{"cat"}, Sources: []controls.Source{{Title: "t2", URL: "u2"}},
			Description: "d2", EvidenceType: controls.EvidenceOutOfScope,
			OutOfScopeReason: "na",
		},
	}

	for max := 0; max <= 30; max++ {
		w := &limitWriter{max: max}
		err := renderControlsText(w, sample)
		if err == nil {
			break
		}
	}
}
