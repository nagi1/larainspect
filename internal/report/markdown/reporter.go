package markdown

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
	return "markdown"
}

func (reporter Reporter) Render(writer io.Writer, report model.Report) error {
	var builder strings.Builder

	fmt.Fprintln(&builder, "# Larainspect Audit Report")
	fmt.Fprintln(&builder)
	fmt.Fprintf(&builder, "- Host: `%s`\n", reportfmt.DefaultString(report.Host.Hostname, "unknown"))
	fmt.Fprintf(&builder, "- Schema: `%s`\n", report.SchemaVersion)
	fmt.Fprintf(&builder, "- Generated: `%s`\n", report.GeneratedAt.Format("2006-01-02 15:04:05Z07:00"))
	fmt.Fprintf(&builder, "- Duration: `%s`\n", report.Duration)
	fmt.Fprintf(&builder, "- Result: `%s` (exit code `%d`)\n", reportfmt.ReportResultLabel(report), model.ExitCodeForReport(report))
	fmt.Fprintln(&builder)

	fmt.Fprintln(&builder, "## Audit Summary")
	fmt.Fprintln(&builder)
	fmt.Fprintln(&builder, "| Metric | Value |")
	fmt.Fprintln(&builder, "| --- | --- |")
	fmt.Fprintf(&builder, "| Total findings | %d |\n", report.Summary.TotalFindings)
	fmt.Fprintf(&builder, "| Direct findings | %d |\n", report.Summary.DirectFindings)
	fmt.Fprintf(&builder, "| Heuristic findings | %d |\n", report.Summary.HeuristicFindings)
	fmt.Fprintf(&builder, "| Possible compromise indicators | %d |\n", report.Summary.CompromiseIndicators)
	fmt.Fprintf(&builder, "| Unknowns | %d |\n", report.Summary.Unknowns)
	for _, severity := range reportfmt.OrderedSeverities() {
		fmt.Fprintf(&builder, "| %s | %d |\n", severity, report.Summary.SeverityCounts[severity])
	}
	fmt.Fprintln(&builder)

	writePriorityQueueMarkdown(&builder, report)
	writeFindingSectionMarkdown(&builder, "Direct Findings", report.DirectFindings)
	writeFindingSectionMarkdown(&builder, "Heuristic Findings", report.HeuristicFindings)
	writeFindingSectionMarkdown(&builder, "Possible Compromise Indicators", report.CompromiseIndicators)
	writeUnknownSectionMarkdown(&builder, report.Unknowns)

	_, err := io.WriteString(writer, builder.String())
	return err
}

func writePriorityQueueMarkdown(builder *strings.Builder, report model.Report) {
	priorityItems := buildPriorityItems(report)

	fmt.Fprintln(builder, "## Priority Queue")
	fmt.Fprintln(builder)
	if len(priorityItems) == 0 {
		fmt.Fprintln(builder, "No critical, high, or unknown items were promoted into the priority queue.")
		fmt.Fprintln(builder)
		return
	}

	for index, item := range priorityItems {
		fmt.Fprintf(builder, "%d. %s\n", index+1, item)
	}
	fmt.Fprintln(builder)
}

func writeFindingSectionMarkdown(builder *strings.Builder, title string, findings []model.Finding) {
	fmt.Fprintf(builder, "## %s (%d)\n\n", title, len(findings))
	if len(findings) == 0 {
		fmt.Fprintln(builder, "None.")
		fmt.Fprintln(builder)
		return
	}

	sortedFindings := append([]model.Finding(nil), findings...)
	reportfmt.SortFindings(sortedFindings)

	for _, finding := range sortedFindings {
		fmt.Fprintf(builder, "### %s\n\n", finding.Title)
		fmt.Fprintf(builder, "- Severity: `%s`\n", finding.Severity)
		fmt.Fprintf(builder, "- Confidence: `%s`\n", finding.Confidence)
		fmt.Fprintf(builder, "- Check ID: `%s`\n", finding.CheckID)
		fmt.Fprintf(builder, "- Class: `%s`\n", reportfmt.FindingClassLabel(finding.Class))
		fmt.Fprintf(builder, "- Why: %s\n", finding.Why)
		if len(finding.Affected) > 0 {
			fmt.Fprintln(builder, "- Affected:")
			for _, target := range finding.Affected {
				fmt.Fprintf(builder, "  - `%s`\n", reportfmt.DescribeTarget(target))
			}
		}
		if len(finding.Evidence) > 0 {
			fmt.Fprintln(builder, "- Evidence:")
			for _, evidence := range finding.Evidence {
				fmt.Fprintf(builder, "  - **%s:** %s\n", evidence.Label, evidence.Detail)
			}
		}
		relatedControls := controls.ForFinding(finding.CheckID, finding.ID)
		if len(relatedControls) > 0 {
			fmt.Fprintln(builder, "- Controls:")
			for _, control := range relatedControls {
				fmt.Fprintf(builder, "  - `%s` `%s` %s\n", control.ID, control.Status, control.Name)
			}
		}
		fmt.Fprintf(builder, "- Remediation: %s\n\n", finding.Remediation)
	}
}

func writeUnknownSectionMarkdown(builder *strings.Builder, unknowns []model.Unknown) {
	fmt.Fprintf(builder, "## Unknowns (%d)\n\n", len(unknowns))
	if len(unknowns) == 0 {
		fmt.Fprintln(builder, "None.")
		fmt.Fprintln(builder)
		return
	}

	for _, unknown := range unknowns {
		fmt.Fprintf(builder, "### %s\n\n", unknown.Title)
		fmt.Fprintf(builder, "- Error kind: `%s`\n", unknown.Error)
		fmt.Fprintf(builder, "- Check ID: `%s`\n", unknown.CheckID)
		fmt.Fprintf(builder, "- Reason: %s\n", unknown.Reason)
		if len(unknown.Affected) > 0 {
			fmt.Fprintln(builder, "- Affected:")
			for _, target := range unknown.Affected {
				fmt.Fprintf(builder, "  - `%s`\n", reportfmt.DescribeTarget(target))
			}
		}
		if len(unknown.Evidence) > 0 {
			fmt.Fprintln(builder, "- Evidence:")
			for _, evidence := range unknown.Evidence {
				fmt.Fprintf(builder, "  - **%s:** %s\n", evidence.Label, evidence.Detail)
			}
		}
		fmt.Fprintln(builder)
	}
}

func buildPriorityItems(report model.Report) []string {
	items := make([]string, 0, 6)

	for _, entry := range reportfmt.PriorityEntries(report) {
		if entry.Unknown {
			items = append(items, fmt.Sprintf("`UNKNOWN` `%s` %s", strings.ToUpper(string(entry.ErrorKind)), entry.Title))
			continue
		}

		items = append(items, fmt.Sprintf("`%s` `%s` %s", strings.ToUpper(string(entry.Severity)), reportfmt.PriorityClassLabel(entry.Class), entry.Title))
	}

	return items
}
