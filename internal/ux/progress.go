package ux

import (
	"fmt"
	"io"
	"strings"

	"github.com/nagi1/larainspect/internal/model"
	"github.com/nagi1/larainspect/internal/progress"
)

type ProgressPrinter struct {
	writer        io.Writer
	verbosity     model.Verbosity
	screenReader  bool
	headerWritten bool
	stageOrder    map[progress.Stage]int
	stageTotal    int
	state         *progress.State
}

func NewProgressPrinter(writer io.Writer, config model.AuditConfig) ProgressPrinter {
	stageOrder := map[progress.Stage]int{}
	orderedStages := progress.OrderedStages()
	for index, stage := range orderedStages {
		stageOrder[stage] = index + 1
	}

	return ProgressPrinter{
		writer:       writer,
		verbosity:    config.Verbosity,
		screenReader: config.ScreenReader,
		stageOrder:   stageOrder,
		stageTotal:   len(orderedStages),
		state:        progress.NewState(50),
	}
}

func (printer *ProgressPrinter) Handle(event progress.Event) {
	if printer == nil || printer.writer == nil || printer.verbosity == model.VerbosityQuiet {
		return
	}

	if printer.state != nil {
		printer.state.Handle(event)
	}

	printer.writeHeader()

	switch event.Type {
	case progress.EventStageStarted:
		printer.writeStageStart(event)
	case progress.EventStageCompleted:
		printer.writeStageCompletion(event)
	case progress.EventContextResolved:
		printer.writeContextSummary()
	case progress.EventCheckRegistered:
		printer.writeComponentRegistration("check", event)
	case progress.EventCheckStarted:
		printer.writeComponentStart("check", event)
	case progress.EventCheckCompleted:
		printer.writeComponentSummary("check", event)
	case progress.EventCorrelatorCompleted:
		printer.writeComponentSummary("correlator", event)
	case progress.EventCorrelatorRegistered:
		printer.writeComponentRegistration("correlator", event)
	case progress.EventCorrelatorStarted:
		printer.writeComponentStart("correlator", event)
	case progress.EventCheckFailed:
		printer.writeComponentFailure("check", event)
	case progress.EventCorrelatorFailed:
		printer.writeComponentFailure("correlator", event)
	case progress.EventFindingDiscovered:
		printer.writeFinding(event)
	case progress.EventUnknownObserved:
		printer.writeUnknown(event)
	case progress.EventAuditFailed:
		printer.writeFailure(event)
	}
}

func (printer *ProgressPrinter) writeHeader() {
	if printer.headerWritten {
		return
	}

	fmt.Fprintln(printer.writer, "Audit progress")
	fmt.Fprintln(printer.writer, "--------------")
	fmt.Fprintln(printer.writer, "Stages: Setup -> Discovery -> Checks -> Correlation -> Post-Process -> Report")
	printer.headerWritten = true
}

func (printer *ProgressPrinter) writeStageStart(event progress.Event) {
	index := printer.stageOrder[event.Stage]
	if index == 0 {
		index = 1
	}

	line := fmt.Sprintf("[%d/%d] %s", index, printer.stageTotal, event.Stage.Label())
	if strings.TrimSpace(event.Message) != "" {
		line = fmt.Sprintf("%s: %s", line, event.Message)
	}

	fmt.Fprintln(printer.writer, line)
}

func (printer *ProgressPrinter) writeStageCompletion(event progress.Event) {
	if printer.verbosity != model.VerbosityVerbose {
		return
	}

	if strings.TrimSpace(event.Message) == "" {
		return
	}

	fmt.Fprintf(printer.writer, "      complete: %s\n", event.Message)
}

func (printer *ProgressPrinter) writeComponentSummary(componentKind string, event progress.Event) {
	if printer.verbosity == model.VerbosityVerbose {
		name := event.ComponentID
		if strings.TrimSpace(name) == "" {
			name = "unknown"
		}

		fmt.Fprintf(
			printer.writer,
			"      %s %s complete%s: +%d findings, +%d unknowns\n",
			componentKind,
			name,
			printer.componentProgress(event),
			event.Findings,
			event.Unknowns,
		)
	}

	printer.writeLiveTotals()
}

func (printer *ProgressPrinter) writeContextSummary() {
	if printer.state == nil {
		return
	}

	context := printer.state.Snapshot().Context
	parts := []string{fmt.Sprintf("apps=%d", context.AppCount)}

	if trimmedName := strings.TrimSpace(context.AppName); trimmedName != "" {
		parts = append(parts, fmt.Sprintf("primary=%s", trimmedName))
	} else if trimmedPath := strings.TrimSpace(context.AppPath); trimmedPath != "" {
		parts = append(parts, fmt.Sprintf("primary=%s", trimmedPath))
	}
	if trimmedVersion := strings.TrimSpace(context.LaravelVersion); trimmedVersion != "" {
		parts = append(parts, fmt.Sprintf("laravel=%s", trimmedVersion))
	}
	if trimmedVersion := strings.TrimSpace(context.PHPVersion); trimmedVersion != "" {
		parts = append(parts, fmt.Sprintf("php=%s", trimmedVersion))
	}
	if context.PackageCount > 0 {
		parts = append(parts, fmt.Sprintf("packages=%d", context.PackageCount))
	}
	if context.SourceMatches > 0 {
		parts = append(parts, fmt.Sprintf("source_matches=%d", context.SourceMatches))
	}
	if context.ArtifactCount > 0 {
		parts = append(parts, fmt.Sprintf("artifacts=%d", context.ArtifactCount))
	}
	if context.NginxSites > 0 {
		parts = append(parts, fmt.Sprintf("nginx=%d", context.NginxSites))
	}
	if context.PHPFPMPools > 0 {
		parts = append(parts, fmt.Sprintf("php_fpm=%d", context.PHPFPMPools))
	}
	if context.Listeners > 0 {
		parts = append(parts, fmt.Sprintf("listeners=%d", context.Listeners))
	}

	fmt.Fprintf(printer.writer, "      context: %s\n", strings.Join(parts, " "))
}

func (printer *ProgressPrinter) writeLiveTotals() {
	if printer.state == nil {
		return
	}

	snapshot := printer.state.Snapshot()
	if snapshot.FindingsDiscovered == 0 && snapshot.UnknownsObserved == 0 {
		return
	}

	fmt.Fprintf(
		printer.writer,
		"      live totals: findings=%d unknowns=%d critical=%d high=%d medium=%d low=%d informational=%d\n",
		snapshot.FindingsDiscovered,
		snapshot.UnknownsObserved,
		snapshot.SeverityCounts[model.SeverityCritical],
		snapshot.SeverityCounts[model.SeverityHigh],
		snapshot.SeverityCounts[model.SeverityMedium],
		snapshot.SeverityCounts[model.SeverityLow],
		snapshot.SeverityCounts[model.SeverityInformational],
	)
}

func (printer *ProgressPrinter) writeComponentRegistration(componentKind string, event progress.Event) {
	if printer.verbosity != model.VerbosityVerbose {
		return
	}

	name := event.ComponentID
	if strings.TrimSpace(name) == "" {
		name = "unknown"
	}

	line := fmt.Sprintf("      registered %s %s", componentKind, name)
	if strings.TrimSpace(event.Message) != "" {
		line = fmt.Sprintf("%s: %s", line, event.Message)
	}

	fmt.Fprintln(printer.writer, line)
}

func (printer *ProgressPrinter) writeComponentStart(componentKind string, event progress.Event) {
	if printer.verbosity != model.VerbosityVerbose {
		return
	}

	name := event.ComponentID
	if strings.TrimSpace(name) == "" {
		name = "unknown"
	}

	fmt.Fprintf(printer.writer, "      starting %s %s%s\n", componentKind, name, printer.componentProgress(event))
}

func (printer *ProgressPrinter) writeComponentFailure(componentKind string, event progress.Event) {
	name := event.ComponentID
	if strings.TrimSpace(name) == "" {
		name = "unknown"
	}

	message := fmt.Sprintf("%s %s failed", componentKind, name)
	if event.Err != nil {
		message = fmt.Sprintf("%s: %v", message, event.Err)
	}

	fmt.Fprintf(printer.writer, "      %s%s\n", message, printer.componentProgress(event))
}

func (printer *ProgressPrinter) writeFailure(event progress.Event) {
	if event.Err == nil {
		return
	}

	if printer.screenReader {
		fmt.Fprintf(printer.writer, "Audit failed: %v\n", event.Err)
		return
	}

	fmt.Fprintf(printer.writer, "Audit failed before report rendering: %v\n", event.Err)
}

func (printer *ProgressPrinter) writeFinding(event progress.Event) {
	if printer.verbosity != model.VerbosityVerbose {
		return
	}

	title := strings.TrimSpace(event.Title)
	if title == "" {
		title = "untitled finding"
	}

	fmt.Fprintf(
		printer.writer,
		"      finding [%s][%s] %s\n",
		strings.ToUpper(string(event.Severity)),
		classLabel(event.Class),
		title,
	)
}

func (printer *ProgressPrinter) writeUnknown(event progress.Event) {
	if printer.verbosity != model.VerbosityVerbose {
		return
	}

	title := strings.TrimSpace(event.Title)
	if title == "" {
		title = "untitled unknown"
	}

	fmt.Fprintf(
		printer.writer,
		"      unknown [%s] %s\n",
		strings.ToUpper(string(event.ErrorKind)),
		title,
	)
}

func (printer *ProgressPrinter) componentProgress(event progress.Event) string {
	if event.Total <= 0 {
		return ""
	}

	completed := event.Completed
	if printer.state != nil {
		snapshot := printer.state.Snapshot()
		switch event.Type {
		case progress.EventCheckStarted, progress.EventCheckCompleted, progress.EventCheckFailed:
			if snapshot.CheckTotal > 0 {
				return fmt.Sprintf(" [%d/%d]", maxCount(completed, snapshot.CheckCompleted), snapshot.CheckTotal)
			}
		case progress.EventCorrelatorStarted, progress.EventCorrelatorCompleted, progress.EventCorrelatorFailed:
			if snapshot.CorrelatorTotal > 0 {
				return fmt.Sprintf(" [%d/%d]", maxCount(completed, snapshot.CorrelatorCompleted), snapshot.CorrelatorTotal)
			}
		}
	}

	return fmt.Sprintf(" [%d/%d]", completed, event.Total)
}

func maxCount(left int, right int) int {
	if right > left {
		return right
	}

	return left
}

func classLabel(class model.FindingClass) string {
	switch class {
	case model.FindingClassDirect:
		return "DIRECT"
	case model.FindingClassHeuristic:
		return "HEURISTIC"
	case model.FindingClassCompromiseIndicator:
		return "COMPROMISE"
	default:
		return strings.ToUpper(string(class))
	}
}
