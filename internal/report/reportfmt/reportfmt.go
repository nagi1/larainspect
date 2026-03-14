package reportfmt

import (
	"fmt"
	"sort"
	"strings"

	"github.com/nagi1/larainspect/internal/model"
)

type PriorityEntry struct {
	Severity  model.Severity
	Class     model.FindingClass
	ErrorKind model.ErrorKind
	Title     string
	Unknown   bool
}

func DefaultString(value string, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}

	return value
}

func ReportResultLabel(report model.Report) string {
	result := report.HighestSeverityOrClean()
	if result == "clean" || result == "unknown-only" {
		return result
	}

	return result + " risk"
}

func DescribeTarget(target model.Target) string {
	if target.Path != "" {
		return target.Path
	}
	if target.Name != "" && target.Value != "" {
		return fmt.Sprintf("%s=%s", target.Name, target.Value)
	}
	if target.Name != "" {
		return target.Name
	}
	if target.Value != "" {
		return target.Value
	}
	if target.Type != "" {
		return target.Type
	}

	return "unknown"
}

func FindingClassLabel(class model.FindingClass) string {
	switch class {
	case model.FindingClassDirect:
		return "direct finding"
	case model.FindingClassHeuristic:
		return "heuristic finding"
	case model.FindingClassCompromiseIndicator:
		return "possible compromise indicator"
	default:
		return string(class)
	}
}

func PriorityClassLabel(class model.FindingClass) string {
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

func OrderedSeverities() []model.Severity {
	return []model.Severity{
		model.SeverityCritical,
		model.SeverityHigh,
		model.SeverityMedium,
		model.SeverityLow,
		model.SeverityInformational,
	}
}

func SortFindings(findings []model.Finding) {
	sort.SliceStable(findings, func(leftIndex int, rightIndex int) bool {
		left := findings[leftIndex]
		right := findings[rightIndex]

		leftRank := severityRank(left.Severity)
		rightRank := severityRank(right.Severity)
		if leftRank != rightRank {
			return leftRank < rightRank
		}
		if left.CheckID != right.CheckID {
			return left.CheckID < right.CheckID
		}

		return left.Title < right.Title
	})
}

func PriorityEntries(report model.Report) []PriorityEntry {
	entries := make([]PriorityEntry, 0, len(report.DirectFindings)+len(report.CompromiseIndicators)+len(report.Unknowns))

	appendFindings := func(findings []model.Finding) {
		sortedFindings := append([]model.Finding(nil), findings...)
		SortFindings(sortedFindings)

		for _, finding := range sortedFindings {
			if finding.Severity != model.SeverityCritical && finding.Severity != model.SeverityHigh {
				continue
			}

			entries = append(entries, PriorityEntry{
				Severity: finding.Severity,
				Class:    finding.Class,
				Title:    finding.Title,
			})
		}
	}

	appendFindings(report.DirectFindings)
	appendFindings(report.CompromiseIndicators)

	for _, unknown := range report.Unknowns {
		entries = append(entries, PriorityEntry{
			ErrorKind: unknown.Error,
			Title:     unknown.Title,
			Unknown:   true,
		})
	}

	if len(entries) > 6 {
		return entries[:6]
	}

	return entries
}

func severityRank(severity model.Severity) int {
	for index, candidate := range OrderedSeverities() {
		if severity == candidate {
			return index
		}
	}

	return len(OrderedSeverities())
}
