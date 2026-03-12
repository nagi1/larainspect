package ux

import (
	"fmt"
	"strings"

	"github.com/nagi1/larainspect/internal/model"
)

func Onboarding(config model.AuditConfig) string {
	if config.Verbosity == model.VerbosityQuiet {
		return ""
	}

	lines := []string{
		"Starting read-only audit",
		"This run never changes files, permissions, services, or firewall state.",
		fmt.Sprintf("Scope: %s", describeScope(config)),
		fmt.Sprintf("Output: %s with %s detail", config.Format, config.Verbosity),
	}

	if config.Verbosity == model.VerbosityVerbose {
		lines = append(lines,
			fmt.Sprintf("Interactivity: %s", enabledDisabled(config.Interactive)),
			fmt.Sprintf("Color preference: %s", config.ColorMode),
			fmt.Sprintf("Screen-reader mode: %s", enabledDisabled(config.ScreenReader)),
			fmt.Sprintf("Worker limit: %d", config.WorkerLimit),
		)
	}

	if !config.ScreenReader {
		lines = append(lines, "Tip: use --format json for automation or --verbosity quiet for focused reruns.")
	}

	return strings.Join(lines, "\n") + "\n\n"
}

func Footer(report model.Report, config model.AuditConfig) string {
	if config.Verbosity == model.VerbosityQuiet {
		return ""
	}

	if report.Summary.TotalFindings == 0 && report.Summary.Unknowns == 0 {
		return "Next steps\n----------\nNo risk checks have produced findings in this build yet.\nUse discovery flags like --app-path or --scan-root to validate host evidence collection before later checks land.\n"
	}

	lines := []string{
		"Recommended next steps",
		"----------------------",
		"Review direct findings first, then compromise indicators, then unknowns.",
		"Re-run with --verbosity verbose for more operator guidance or --format json for machine-readable output.",
	}

	if config.Scope == model.ScanScopeAuto && !config.ScreenReader {
		lines = append(lines, "If you want a narrower future run, use --scope app --app-path /path/to/app.")
	}

	return strings.Join(lines, "\n") + "\n"
}

func describeScope(config model.AuditConfig) string {
	switch config.Scope {
	case model.ScanScopeApp:
		if strings.TrimSpace(config.AppPath) == "" {
			return "app-focused run"
		}
		return fmt.Sprintf("app-focused run at %s", config.AppPath)
	case model.ScanScopeHost:
		return "host-wide run"
	default:
		return "automatic scope selection"
	}
}

func enabledDisabled(value bool) string {
	if value {
		return "enabled"
	}

	return "disabled"
}
