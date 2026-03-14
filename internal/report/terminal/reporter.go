package terminal

import (
	"fmt"
	"io"
	"strings"

	"github.com/nagi1/larainspect/internal/controls"
	"github.com/nagi1/larainspect/internal/model"
	"github.com/nagi1/larainspect/internal/report"
	"github.com/nagi1/larainspect/internal/report/reportfmt"
)

var _ report.Reporter = Reporter{}

type Reporter struct{}

func NewReporter() Reporter {
	return Reporter{}
}

func (reporter Reporter) Format() string {
	return "terminal"
}

func (reporter Reporter) Render(writer io.Writer, report model.Report) error {
	if _, err := fmt.Fprintln(writer, "larainspect audit"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(writer, "================="); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(
		writer,
		"Host: %s\nSchema: %s\nGenerated: %s\nDuration: %s\nResult: %s (exit code %d)\n",
		reportfmt.DefaultString(report.Host.Hostname, "unknown"),
		report.SchemaVersion,
		report.GeneratedAt.Format("2006-01-02 15:04:05Z07:00"),
		report.Duration,
		reportfmt.ReportResultLabel(report),
		model.ExitCodeForReport(report),
	); err != nil {
		return err
	}

	writeSectionHeading(writer, "Audit Summary", 0)
	fmt.Fprintf(writer, "Findings: %d total\n", report.Summary.TotalFindings)
	fmt.Fprintf(
		writer,
		"Classes: direct=%d heuristic=%d compromise=%d unknowns=%d\n",
		report.Summary.DirectFindings,
		report.Summary.HeuristicFindings,
		report.Summary.CompromiseIndicators,
		report.Summary.Unknowns,
	)
	fmt.Fprintf(
		writer,
		"Severity: critical=%d high=%d medium=%d low=%d informational=%d\n",
		report.Summary.SeverityCounts[model.SeverityCritical],
		report.Summary.SeverityCounts[model.SeverityHigh],
		report.Summary.SeverityCounts[model.SeverityMedium],
		report.Summary.SeverityCounts[model.SeverityLow],
		report.Summary.SeverityCounts[model.SeverityInformational],
	)

	renderPriorityQueue(writer, report)
	renderFindingSection(writer, "Direct Findings", report.DirectFindings)
	renderFindingSection(writer, "Heuristic Findings", report.HeuristicFindings)
	renderFindingSection(writer, "Possible Compromise Indicators", report.CompromiseIndicators)
	renderUnknownSection(writer, report.Unknowns)

	return nil
}

func renderPriorityQueue(writer io.Writer, report model.Report) {
	writeSectionHeading(writer, "Priority Queue", 0)

	items := buildPriorityItems(report)
	if len(items) == 0 {
		fmt.Fprintln(writer, "No critical, high, or unknown items were promoted into the priority queue.")
		return
	}

	for index, item := range items {
		fmt.Fprintf(writer, "%d. %s\n", index+1, item)
	}
}

func renderFindingSection(writer io.Writer, title string, findings []model.Finding) {
	writeSectionHeading(writer, title, len(findings))
	if len(findings) == 0 {
		fmt.Fprintln(writer, "None.")
		return
	}

	sortedFindings := append([]model.Finding(nil), findings...)
	reportfmt.SortFindings(sortedFindings)

	for index, finding := range sortedFindings {
		fmt.Fprintf(writer, "[%s][%s] %s (%s)\n", strings.ToUpper(string(finding.Severity)), strings.ToUpper(string(finding.Confidence)), finding.Title, finding.CheckID)
		fmt.Fprintf(writer, "Class: %s\n", reportfmt.FindingClassLabel(finding.Class))
		fmt.Fprintf(writer, "Why: %s\n", finding.Why)
		if len(finding.Affected) > 0 {
			fmt.Fprintln(writer, "Affected:")
			for _, target := range finding.Affected {
				fmt.Fprintf(writer, "- %s\n", reportfmt.DescribeTarget(target))
			}
		}
		fmt.Fprintln(writer, "Evidence:")
		for _, evidence := range finding.Evidence {
			fmt.Fprintf(writer, "- %s: %s\n", evidence.Label, evidence.Detail)
		}
		fmt.Fprintf(writer, "Remediation: %s\n", finding.Remediation)
		relatedControls := controls.ForFinding(finding.CheckID, finding.ID)
		if len(relatedControls) > 0 {
			fmt.Fprintln(writer, "Controls:")
			for _, control := range relatedControls {
				fmt.Fprintf(writer, "- %s [%s]: %s\n", control.ID, control.Status, control.Name)
			}
		}
		if index < len(sortedFindings)-1 {
			fmt.Fprintln(writer)
		}
	}
}

func renderUnknownSection(writer io.Writer, unknowns []model.Unknown) {
	writeSectionHeading(writer, "Unknowns", len(unknowns))
	if len(unknowns) == 0 {
		fmt.Fprintln(writer, "None.")
		return
	}

	for index, unknown := range unknowns {
		fmt.Fprintf(writer, "[%s] %s (%s)\n", strings.ToUpper(string(unknown.Error)), unknown.Title, unknown.CheckID)
		fmt.Fprintf(writer, "Reason: %s\n", unknown.Reason)
		if len(unknown.Affected) > 0 {
			fmt.Fprintln(writer, "Affected:")
			for _, target := range unknown.Affected {
				fmt.Fprintf(writer, "- %s\n", reportfmt.DescribeTarget(target))
			}
		}
		if len(unknown.Evidence) > 0 {
			fmt.Fprintln(writer, "Evidence:")
			for _, evidence := range unknown.Evidence {
				fmt.Fprintf(writer, "- %s: %s\n", evidence.Label, evidence.Detail)
			}
		}
		if index < len(unknowns)-1 {
			fmt.Fprintln(writer)
		}
	}
}

func writeSectionHeading(writer io.Writer, title string, count int) {
	fmt.Fprintln(writer)
	if count > 0 {
		title = fmt.Sprintf("%s (%d)", title, count)
	}
	fmt.Fprintln(writer, title)
	fmt.Fprintln(writer, strings.Repeat("-", len(title)))
}

func buildPriorityItems(report model.Report) []string {
	items := make([]string, 0, 6)

	for _, entry := range reportfmt.PriorityEntries(report) {
		if entry.Unknown {
			items = append(items, fmt.Sprintf("[UNKNOWN][%s] %s", strings.ToUpper(string(entry.ErrorKind)), entry.Title))
			continue
		}

		items = append(items, fmt.Sprintf("[%s][%s] %s", strings.ToUpper(string(entry.Severity)), reportfmt.PriorityClassLabel(entry.Class), entry.Title))
	}

	return items
}
