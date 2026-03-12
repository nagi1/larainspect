package cli

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"io"
	"strings"
	"testing"

	"github.com/nagi/larainspect/internal/model"
)

func TestWriteFlagError(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	writeFlagError(&output, errors.New("bad flag"), func(writer io.Writer) {
		_, _ = writer.Write([]byte("usage"))
	})

	if !strings.Contains(output.String(), "bad flag") || !strings.Contains(output.String(), "usage") {
		t.Fatalf("unexpected output %q", output.String())
	}
}

func TestWriteFlagErrorForHelp(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	writeFlagError(&output, flag.ErrHelp, func(writer io.Writer) {
		_, _ = writer.Write([]byte("usage"))
	})

	if output.String() != "usage" {
		t.Fatalf("unexpected output %q", output.String())
	}
}

func TestRunAuditCommandWrapper(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := runAuditCommand(context.Background(), &stdout, &stderr, []string{"--format", "json"})
	if exitCode != int(model.ExitCodeClean) {
		t.Fatalf("expected clean exit code, got %d stderr=%q", exitCode, stderr.String())
	}
}

func TestReporterFor(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		format string
		want   string
		ok     bool
	}{
		{format: "", want: "terminal", ok: true},
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
