package model

type ExitCode int

const (
	ExitCodeClean        ExitCode = 0
	ExitCodeUsageError   ExitCode = 2
	ExitCodeLowRisk      ExitCode = 10
	ExitCodeMediumRisk   ExitCode = 20
	ExitCodeHighRisk     ExitCode = 30
	ExitCodeCriticalRisk ExitCode = 40
	ExitCodeAuditFailed  ExitCode = 50
)

func (report Report) HighestSeverity() Severity {
	for _, severity := range []Severity{
		SeverityCritical,
		SeverityHigh,
		SeverityMedium,
		SeverityLow,
		SeverityInformational,
	} {
		if report.Summary.SeverityCounts[severity] > 0 {
			return severity
		}
	}

	return ""
}

func ExitCodeForReport(report Report) ExitCode {
	switch report.HighestSeverity() {
	case SeverityCritical:
		return ExitCodeCriticalRisk
	case SeverityHigh:
		return ExitCodeHighRisk
	case SeverityMedium:
		return ExitCodeMediumRisk
	case SeverityLow, SeverityInformational:
		return ExitCodeLowRisk
	default:
		if report.Summary.Unknowns > 0 {
			return ExitCodeLowRisk
		}
		return ExitCodeClean
	}
}
