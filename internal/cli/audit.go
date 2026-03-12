package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/nagi/larainspect/internal/checks"
	"github.com/nagi/larainspect/internal/discovery"
	"github.com/nagi/larainspect/internal/model"
	"github.com/nagi/larainspect/internal/report"
	jsonreport "github.com/nagi/larainspect/internal/report/json"
	"github.com/nagi/larainspect/internal/report/terminal"
	"github.com/nagi/larainspect/internal/runner"
)

func runAuditCommand(ctx context.Context, stdout io.Writer, stderr io.Writer, args []string) int {
	flagSet := newFlagSet("audit")
	format := flagSet.String("format", "terminal", "Output format: terminal or json")
	commandTimeout := flagSet.Duration("command-timeout", 2*time.Second, "Timeout for one allowlisted command")
	maxOutputBytes := flagSet.Int("max-output-bytes", 64*1024, "Maximum bytes captured per command stream")
	workerLimit := flagSet.Int("worker-limit", runner.DefaultWorkerLimit(), "Reserved worker cap for bounded concurrency")

	if err := flagSet.Parse(args); err != nil {
		writeFlagError(stderr, err, printAuditHelp)
		return 1
	}

	reporter, err := reporterFor(*format)
	if err != nil {
		fmt.Fprintln(stderr, err)
		fmt.Fprintln(stderr)
		printAuditHelp(stderr)
		return 1
	}

	commandRunner := runner.NewCommandRunner(*commandTimeout, *maxOutputBytes, runner.DefaultAllowlist())
	execution, err := runner.NewExecutionContext(model.AuditConfig{
		Format:         *format,
		CommandTimeout: *commandTimeout,
		MaxOutputBytes: *maxOutputBytes,
		WorkerLimit:    *workerLimit,
	}, commandRunner)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	auditor := runner.Auditor{
		Discovery:   discovery.NoopService{},
		Checks:      checks.Registered(),
		Correlators: nil,
	}

	auditReport, err := auditor.Run(ctx, execution)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	if err := reporter.Render(stdout, auditReport); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	return 0
}

func reporterFor(format string) (report.Reporter, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "terminal", "":
		return terminal.NewReporter(), nil
	case "json":
		return jsonreport.NewReporter(), nil
	default:
		return nil, errors.New("unsupported format; use terminal or json")
	}
}

func printAuditHelp(writer io.Writer) {
	fmt.Fprint(writer, strings.TrimSpace(auditHelp))
	fmt.Fprintln(writer)
}

const auditHelp = `
larainspect audit

Run the foundation audit pipeline.

Usage:
  larainspect audit [flags]

Flags:
  --format string            Output format: terminal or json (default "terminal")
  --command-timeout duration Timeout for one allowlisted command (default 2s)
  --max-output-bytes int     Maximum bytes captured per command stream (default 65536)
  --worker-limit int         Reserved worker cap for bounded concurrency
`
