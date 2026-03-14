package cli

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/nagi1/larainspect/internal/debuglog"
	"github.com/nagi1/larainspect/internal/model"
	"github.com/nagi1/larainspect/internal/orchestrator"
	"github.com/nagi1/larainspect/internal/progress"
	"github.com/nagi1/larainspect/internal/report"
	htmlreport "github.com/nagi1/larainspect/internal/report/html"
	jsonreport "github.com/nagi1/larainspect/internal/report/json"
	markdownreport "github.com/nagi1/larainspect/internal/report/markdown"
	sarifreport "github.com/nagi1/larainspect/internal/report/sarif"
	"github.com/nagi1/larainspect/internal/report/terminal"
	"github.com/nagi1/larainspect/internal/ux"
)

func writeOnboarding(stdout io.Writer, config model.AuditConfig) {
	if !config.UsesTerminalOutput() {
		return
	}

	onboarding := ux.Onboarding(config)
	if onboarding == "" {
		return
	}

	fmt.Fprint(stdout, onboarding)
}

func writeFooter(stdout io.Writer, report model.Report, config model.AuditConfig) {
	if !config.UsesTerminalOutput() {
		return
	}

	footer := ux.Footer(report, config)
	if footer == "" {
		return
	}

	fmt.Fprintf(stdout, "\n%s", footer)
}

func reporterFor(format string) (report.Reporter, error) {
	switch model.NormalizeOutputFormat(format) {
	case model.OutputFormatTerminal:
		return terminal.NewReporter(), nil
	case model.OutputFormatJSON:
		return jsonreport.NewReporter(), nil
	case model.OutputFormatMarkdown:
		return markdownreport.NewReporter(), nil
	default:
		return nil, errors.New("unsupported format; use terminal, json, or markdown")
	}
}

func newProgressBus(stdout io.Writer, config model.AuditConfig, logger *debuglog.Logger) *progress.Bus {
	shouldPrintProgress := config.UsesTerminalOutput() && config.Verbosity != model.VerbosityQuiet
	if !shouldPrintProgress && logger == nil {
		return nil
	}

	bus := progress.NewBus()
	if shouldPrintProgress {
		printer := ux.NewProgressPrinter(stdout, config)
		bus.SubscribeAll(printer.Handle)
	}
	attachDebugLogger(bus, logger)

	return bus
}

func buildAuditOutputs(config model.AuditConfig, stdout io.Writer, stdoutReporter report.Reporter) ([]orchestrator.Output, func(), error) {
	fileOutputs, closeOutputs, err := buildFileOutputs(config)
	if err != nil {
		return nil, func() {}, err
	}

	outputs := append([]orchestrator.Output{{
		Reporter: stdoutReporter,
		Writer:   stdout,
	}}, fileOutputs...)

	return outputs, closeOutputs, nil
}

func buildTUIOutputs(config model.AuditConfig) ([]orchestrator.Output, func(), error) {
	fileOutputs, closeOutputs, err := buildFileOutputs(config)
	if err != nil {
		return nil, func() {}, err
	}

	outputs := append([]orchestrator.Output{{
		Reporter: noopReporter{},
		Writer:   io.Discard,
	}}, fileOutputs...)

	return outputs, closeOutputs, nil
}

// buildFileOutputs creates file-based outputs (JSON, Markdown, SARIF, HTML)
// without any terminal writer. Shared by both the standard and TUI audit paths.
func buildFileOutputs(config model.AuditConfig) ([]orchestrator.Output, func(), error) {
	specs := []fileOutputSpec{
		{path: config.NormalizedReportJSONPath(), reporter: jsonreport.NewReporter()},
		{path: config.NormalizedReportMarkdownPath(), reporter: markdownreport.NewReporter()},
		{path: config.NormalizedReportSARIFPath(), reporter: sarifreport.NewReporter()},
		{path: config.NormalizedReportHTMLPath(), reporter: htmlreport.NewReporter()},
	}

	var outputs []orchestrator.Output
	var closers []io.Closer
	closeAll := func() {
		for _, c := range closers {
			_ = c.Close()
		}
	}

	for _, spec := range specs {
		if spec.path == "" {
			continue
		}

		writer, err := createOutputFile(spec.path)
		if err != nil {
			closeAll()
			return nil, func() {}, err
		}

		closers = append(closers, writer)
		outputs = append(outputs, orchestrator.Output{Reporter: spec.reporter, Writer: writer})
	}

	return outputs, closeAll, nil
}

func closeProgressBus(bus *progress.Bus) {
	if bus == nil {
		return
	}

	bus.Close()
}

type fileOutputSpec struct {
	path     string
	reporter report.Reporter
}

func createOutputFile(path string) (*os.File, error) {
	return os.Create(path)
}

type noopReporter struct{}

func (noopReporter) Format() string {
	return "tui"
}

func (noopReporter) Render(io.Writer, model.Report) error {
	return nil
}
