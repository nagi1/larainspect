package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nagi1/larainspect/internal/debuglog"
	"github.com/nagi1/larainspect/internal/model"
	"github.com/nagi1/larainspect/internal/report/terminal"
)

func TestCommandErrorErrorAndUnwrap(t *testing.T) {

	rootErr := errors.New("bad flag")
	err := &commandError{
		code: int(model.ExitCodeUsageError),
		err:  rootErr,
	}

	if err.Error() != "bad flag" {
		t.Fatalf("unexpected Error() result %q", err.Error())
	}

	if !errors.Is(err, rootErr) {
		t.Fatal("expected Unwrap() to expose the root error")
	}
}

func TestCommandErrorWrite(t *testing.T) {

	var output bytes.Buffer
	newUsageError(errors.New("bad flag"), func(writer io.Writer) {
		_, _ = writer.Write([]byte("usage"))
	}).write(&output)

	if !strings.Contains(output.String(), "bad flag") || !strings.Contains(output.String(), "usage") {
		t.Fatalf("unexpected output %q", output.String())
	}
}

func TestCommandErrorWriteWithoutWrappedError(t *testing.T) {

	var output bytes.Buffer
	(&commandError{code: int(model.ExitCodeUsageError), usage: func(writer io.Writer) {
		_, _ = writer.Write([]byte("usage"))
	}}).write(&output)

	if output.String() != "usage" {
		t.Fatalf("unexpected output %q", output.String())
	}
}

func TestRunAuditCommandWrapper(t *testing.T) {
	appPath := createLaravelAppFixture(t)
	configPath := createDeterministicAuditConfigFile(t)

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := runAuditCommand(context.Background(), &stdout, &stderr, []string{"--config", configPath, "--format", "json", "--scope", "app", "--app-path", appPath})
	if exitCode != int(model.ExitCodeClean) && exitCode != int(model.ExitCodeLowRisk) {
		t.Fatalf("expected clean or low-risk exit code, got %d stderr=%q", exitCode, stderr.String())
	}
}

func TestRunAuditCommandWithInputReturnsHelp(t *testing.T) {

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := runAuditCommandWithInput(context.Background(), strings.NewReader(""), &stdout, &stderr, []string{"--help"})
	if exitCode != 0 {
		t.Fatalf("expected help exit code, got %d stderr=%q", exitCode, stderr.String())
	}

	if !strings.Contains(stdout.String(), "Run the read-only audit workflow.") {
		t.Fatalf("expected audit help output, got %q", stdout.String())
	}
}

func TestRunAuditCommandWithInputReturnsUsageForFlagError(t *testing.T) {

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := runAuditCommandWithInput(context.Background(), strings.NewReader(""), &stdout, &stderr, []string{"--command-timeout", "bad"})
	if exitCode != int(model.ExitCodeUsageError) {
		t.Fatalf("expected usage exit code, got %d", exitCode)
	}

	if !strings.Contains(stderr.String(), "invalid argument") {
		t.Fatalf("expected flag parse error, got %q", stderr.String())
	}
}

func TestNewProgressBus(t *testing.T) {

	var terminal bytes.Buffer
	bus := newProgressBus(&terminal, model.AuditConfig{
		Format:    model.OutputFormatTerminal,
		Verbosity: model.VerbosityNormal,
	}, nil)
	if bus == nil {
		t.Fatal("expected terminal normal mode to create a progress bus")
	}

	if got := newProgressBus(&terminal, model.AuditConfig{
		Format:    model.OutputFormatJSON,
		Verbosity: model.VerbosityVerbose,
	}, nil); got != nil {
		t.Fatal("expected json mode to suppress progress bus")
	}

	if got := newProgressBus(&terminal, model.AuditConfig{
		Format:    model.OutputFormatTerminal,
		Verbosity: model.VerbosityQuiet,
	}, nil); got != nil {
		t.Fatal("expected quiet mode to suppress progress bus")
	}

	if got := newProgressBus(&terminal, model.AuditConfig{
		Format:    model.OutputFormatJSON,
		Verbosity: model.VerbosityQuiet,
	}, debuglog.New(io.Discard)); got == nil {
		t.Fatal("expected debug logging to force creation of a progress bus")
	}
}

func TestReporterFor(t *testing.T) {

	testCases := []struct {
		format string
		want   string
		ok     bool
	}{
		{format: "terminal", want: "terminal", ok: true},
		{format: "json", want: "json", ok: true},
		{format: "bad", ok: false},
	}

	for _, testCase := range testCases {
		reporter, err := reporterFor(testCase.format)
		if testCase.ok {
			if err != nil {
				t.Fatalf("reporterFor(%q) error = %v", testCase.format, err)
			}
			if reporter.Format() != testCase.want {
				t.Fatalf("reporterFor(%q) = %q, want %q", testCase.format, reporter.Format(), testCase.want)
			}
			continue
		}

		if err == nil {
			t.Fatalf("expected error for format %q", testCase.format)
		}
	}
}

func TestBuildAuditOutputs(t *testing.T) {

	var stdout bytes.Buffer
	outputs, closeOutputs, err := buildAuditOutputs(model.AuditConfig{
		Format:         model.OutputFormatTerminal,
		ReportJSONPath: filepath.Join(t.TempDir(), "report.json"),
	}, &stdout, terminal.NewReporter())
	if err != nil {
		t.Fatalf("buildAuditOutputs() error = %v", err)
	}
	defer closeOutputs()

	if len(outputs) != 2 {
		t.Fatalf("expected stdout and json file outputs, got %d", len(outputs))
	}

	if outputs[0].Reporter.Format() != model.OutputFormatTerminal || outputs[1].Reporter.Format() != model.OutputFormatJSON {
		t.Fatalf("unexpected output formats %+v", outputs)
	}
}

func TestBuildAuditOutputsWithoutArtifactPath(t *testing.T) {

	var stdout bytes.Buffer
	outputs, closeOutputs, err := buildAuditOutputs(model.AuditConfig{
		Format: model.OutputFormatTerminal,
	}, &stdout, terminal.NewReporter())
	if err != nil {
		t.Fatalf("buildAuditOutputs() error = %v", err)
	}
	defer closeOutputs()

	if len(outputs) != 1 {
		t.Fatalf("expected only stdout output, got %d", len(outputs))
	}
}

func TestBuildTUIOutputsIncludesNoopReporter(t *testing.T) {

	outputs, closeOutputs, err := buildTUIOutputs(model.AuditConfig{})
	if err != nil {
		t.Fatalf("buildTUIOutputs() error = %v", err)
	}
	defer closeOutputs()

	if len(outputs) != 1 {
		t.Fatalf("expected noop output only, got %d", len(outputs))
	}
	if outputs[0].Reporter.Format() != "tui" {
		t.Fatalf("expected noop TUI reporter, got %q", outputs[0].Reporter.Format())
	}
}

func TestBuildAuditOutputsReturnsFileError(t *testing.T) {

	var stdout bytes.Buffer
	_, closeOutputs, err := buildAuditOutputs(model.AuditConfig{
		Format:         model.OutputFormatTerminal,
		ReportJSONPath: filepath.Join(t.TempDir(), "missing", "report.json"),
	}, &stdout, terminal.NewReporter())
	defer closeOutputs()

	if err == nil {
		t.Fatal("expected file creation error")
	}
}

func TestWriteUsageError(t *testing.T) {

	var output bytes.Buffer
	exitCode := writeUsageError(&output, errors.New("bad input"), true)
	if exitCode != int(model.ExitCodeUsageError) {
		t.Fatalf("expected usage exit code, got %d", exitCode)
	}
	if !strings.Contains(output.String(), "bad input") || !strings.Contains(output.String(), "larainspect audit") {
		t.Fatalf("unexpected usage output %q", output.String())
	}
}

func TestWriteUsageErrorWithoutHelp(t *testing.T) {

	var output bytes.Buffer
	exitCode := writeUsageError(&output, errors.New("bad input"), false)
	if exitCode != int(model.ExitCodeUsageError) {
		t.Fatalf("expected usage exit code, got %d", exitCode)
	}

	if strings.Contains(output.String(), "larainspect audit") {
		t.Fatalf("expected help output to be suppressed, got %q", output.String())
	}
}

func TestCommandErrorNilReceiver(t *testing.T) {

	var nilErr *commandError
	if nilErr.Error() != "" {
		t.Fatalf("nil commandError.Error() should be empty, got %q", nilErr.Error())
	}
	if nilErr.Unwrap() != nil {
		t.Fatal("nil commandError.Unwrap() should return nil")
	}

	var output bytes.Buffer
	nilErr.write(&output)
	if output.Len() != 0 {
		t.Fatalf("nil commandError.write() should not write anything, got %q", output.String())
	}
}

func TestCommandErrorWithNilInnerError(t *testing.T) {

	err := &commandError{code: 1, err: nil}
	if err.Error() != "" {
		t.Fatalf("nil inner err should give empty Error(), got %q", err.Error())
	}
}

func TestCommandErrorWriteWithOnlyUsage(t *testing.T) {

	var output bytes.Buffer
	err := &commandError{
		code:  1,
		err:   nil,
		usage: func(w io.Writer) { _, _ = w.Write([]byte("USAGE")) },
	}
	err.write(&output)
	if output.String() != "USAGE" {
		t.Fatalf("expected only usage output, got %q", output.String())
	}
}
