package terminal

import (
	"fmt"
	"io"
	"strings"

	"github.com/nagi/larainspect/internal/model"
)

type Reporter struct{}

func NewReporter() Reporter {
	return Reporter{}
}

func (reporter Reporter) Format() string {
	return "terminal"
}

func (reporter Reporter) Render(writer io.Writer, report model.Report) error {
	if _, err := fmt.Fprintf(
		writer,
		"larainspect audit\nHost: %s\nSchema: %s\nGenerated: %s\nDuration: %s\n\nSummary: critical=%d high=%d medium=%d low=%d informational=%d unknowns=%d\n",
		defaultString(report.Host.Hostname, "unknown"),
		report.SchemaVersion,
		report.GeneratedAt.Format("2006-01-02 15:04:05Z07:00"),
		report.Duration,
		report.Summary.SeverityCounts[model.SeverityCritical],
		report.Summary.SeverityCounts[model.SeverityHigh],
		report.Summary.SeverityCounts[model.SeverityMedium],
		report.Summary.SeverityCounts[model.SeverityLow],
		report.Summary.SeverityCounts[model.SeverityInformational],
		report.Summary.Unknowns,
	); err != nil {
		return err
	}

	renderFindingSection(writer, "Direct Findings", report.DirectFindings)
	renderFindingSection(writer, "Heuristic Findings", report.HeuristicFindings)
	renderFindingSection(writer, "Possible Compromise Indicators", report.CompromiseIndicators)
	renderUnknownSection(writer, report.Unknowns)

	return nil
}

func renderFindingSection(writer io.Writer, title string, findings []model.Finding) {
	fmt.Fprintf(writer, "\n%s\n", title)
	fmt.Fprintf(writer, "%s\n", strings.Repeat("-", len(title)))
	if len(findings) == 0 {
		fmt.Fprintln(writer, "None.")
		return
	}

	for _, finding := range findings {
		fmt.Fprintf(writer, "[%s][%s] %s (%s)\n", strings.ToUpper(string(finding.Severity)), strings.ToUpper(string(finding.Confidence)), finding.Title, finding.CheckID)
		fmt.Fprintf(writer, "Why: %s\n", finding.Why)

		if len(finding.Affected) > 0 {
			targets := make([]string, 0, len(finding.Affected))
			for _, target := range finding.Affected {
				targets = append(targets, describeTarget(target))
			}
			fmt.Fprintf(writer, "Affected: %s\n", strings.Join(targets, ", "))
		}

		fmt.Fprintln(writer, "Evidence:")
		for _, evidence := range finding.Evidence {
			fmt.Fprintf(writer, "- %s: %s\n", evidence.Label, evidence.Detail)
		}
		fmt.Fprintf(writer, "Remediation: %s\n\n", finding.Remediation)
	}
}

func renderUnknownSection(writer io.Writer, unknowns []model.Unknown) {
	const title = "Unknowns"

	fmt.Fprintf(writer, "\n%s\n", title)
	fmt.Fprintf(writer, "%s\n", strings.Repeat("-", len(title)))
	if len(unknowns) == 0 {
		fmt.Fprintln(writer, "None.")
		return
	}

	for index, unknown := range unknowns {
		fmt.Fprintf(writer, "[%s] %s (%s)\n", strings.ToUpper(string(unknown.Error)), unknown.Title, unknown.CheckID)
		fmt.Fprintf(writer, "Reason: %s\n", unknown.Reason)

		if len(unknown.Affected) > 0 {
			targets := make([]string, 0, len(unknown.Affected))
			for _, target := range unknown.Affected {
				targets = append(targets, describeTarget(target))
			}
			fmt.Fprintf(writer, "Affected: %s\n", strings.Join(targets, ", "))
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

func describeTarget(target model.Target) string {
	if target.Path != "" {
		return target.Path
	}
	if target.Name != "" && target.Value != "" {
		return fmt.Sprintf("%s=%s", target.Name, target.Value)
	}
	if target.Name != "" {
		return target.Name
	}
	return target.Value
}

func defaultString(value string, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}

	return value
}
