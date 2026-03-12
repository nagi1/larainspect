package model

import (
	"fmt"
	"strings"
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

func (config AuditConfig) Validate() error {
	if strings.TrimSpace(config.Format) == "" {
		return fmt.Errorf("format is required")
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

	return nil
}
