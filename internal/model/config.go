package model

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"
)

const (
	OutputFormatTerminal = "terminal"
	OutputFormatJSON     = "json"
)

type Verbosity string

const (
	VerbosityQuiet   Verbosity = "quiet"
	VerbosityNormal  Verbosity = "normal"
	VerbosityVerbose Verbosity = "verbose"
)

func (verbosity Verbosity) Valid() bool {
	switch verbosity {
	case VerbosityQuiet, VerbosityNormal, VerbosityVerbose:
		return true
	default:
		return false
	}
}

type ScanScope string

const (
	ScanScopeAuto ScanScope = "auto"
	ScanScopeHost ScanScope = "host"
	ScanScopeApp  ScanScope = "app"
)

func (scope ScanScope) Valid() bool {
	switch scope {
	case ScanScopeAuto, ScanScopeHost, ScanScopeApp:
		return true
	default:
		return false
	}
}

type ColorMode string

const (
	ColorModeAuto   ColorMode = "auto"
	ColorModeAlways ColorMode = "always"
	ColorModeNever  ColorMode = "never"
)

func (mode ColorMode) Valid() bool {
	switch mode {
	case ColorModeAuto, ColorModeAlways, ColorModeNever:
		return true
	default:
		return false
	}
}

func NormalizeOutputFormat(format string) string {
	return strings.ToLower(strings.TrimSpace(format))
}

func IsValidOutputFormat(format string) bool {
	switch NormalizeOutputFormat(format) {
	case OutputFormatTerminal, OutputFormatJSON:
		return true
	default:
		return false
	}
}

func (config AuditConfig) UsesTerminalOutput() bool {
	return NormalizeOutputFormat(config.Format) == OutputFormatTerminal
}

func (config AuditConfig) ShouldDiscoverApplications() bool {
	return config.Scope != ScanScopeHost
}

func (config AuditConfig) NormalizedScanRoots() []string {
	normalizedRoots := make([]string, 0, len(config.ScanRoots))
	seenRoots := map[string]struct{}{}

	for _, root := range config.ScanRoots {
		trimmedRoot := strings.TrimSpace(root)
		if trimmedRoot == "" {
			continue
		}

		cleanRoot := filepath.Clean(trimmedRoot)
		if _, alreadySeen := seenRoots[cleanRoot]; alreadySeen {
			continue
		}

		seenRoots[cleanRoot] = struct{}{}
		normalizedRoots = append(normalizedRoots, cleanRoot)
	}

	slices.Sort(normalizedRoots)

	return normalizedRoots
}

func (config AuditConfig) Validate() error {
	if strings.TrimSpace(config.Format) == "" {
		return fmt.Errorf("format is required")
	}
	if !IsValidOutputFormat(config.Format) {
		return fmt.Errorf("format %q is invalid", config.Format)
	}
	if !config.Verbosity.Valid() {
		return fmt.Errorf("verbosity %q is invalid", config.Verbosity)
	}
	if !config.Scope.Valid() {
		return fmt.Errorf("scope %q is invalid", config.Scope)
	}
	if !config.ColorMode.Valid() {
		return fmt.Errorf("color mode %q is invalid", config.ColorMode)
	}
	if !IsSupportedOSFamily(config.Profile.OSFamily) {
		return fmt.Errorf("os family %q is invalid", config.Profile.OSFamily)
	}

	return nil
}

func (config AuditConfig) ValidateResolved() error {
	if config.Scope == ScanScopeApp && strings.TrimSpace(config.AppPath) == "" {
		return fmt.Errorf("scope=app requires --app-path, or re-run with --interactive for guided input")
	}

	return nil
}
