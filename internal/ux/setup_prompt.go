package ux

import (
	"bufio"
	"fmt"
	"strings"

	"github.com/nagi1/larainspect/internal/model"
)

type SetupAnswers struct {
	Preset   string
	OSFamily string
	Scope    model.ScanScope
	AppPath  string
}

func (prompter Prompter) ResolveSetupAnswers(defaults SetupAnswers) (SetupAnswers, error) {
	reader := bufio.NewReader(prompter.Input)

	if _, err := fmt.Fprintln(prompter.Output, "Could not confidently detect the hosting preset. Answer a few questions to generate a config."); err != nil {
		return SetupAnswers{}, err
	}

	preset, err := prompter.promptLine(reader, fmt.Sprintf("Hosting preset [forge/digitalocean/aapanel/cpanel/vps] (default %s): ", strings.TrimSpace(defaults.Preset)))
	if err != nil {
		return SetupAnswers{}, err
	}
	if strings.TrimSpace(preset) == "" {
		preset = defaults.Preset
	}

	osFamily, err := prompter.promptLine(reader, fmt.Sprintf("OS family [auto/debian/rhel/custom] (default %s): ", strings.TrimSpace(defaults.OSFamily)))
	if err != nil {
		return SetupAnswers{}, err
	}
	if strings.TrimSpace(osFamily) == "" {
		osFamily = defaults.OSFamily
	}

	scope, err := prompter.promptLine(reader, fmt.Sprintf("Audit scope [%s/%s/%s] (default %s): ", model.ScanScopeAuto, model.ScanScopeHost, model.ScanScopeApp, defaults.Scope))
	if err != nil {
		return SetupAnswers{}, err
	}
	resolvedScope := defaults.Scope
	if strings.TrimSpace(scope) != "" {
		resolvedScope = model.ScanScope(strings.ToLower(strings.TrimSpace(scope)))
		if !resolvedScope.Valid() {
			return SetupAnswers{}, fmt.Errorf("invalid interactive scope %q", scope)
		}
	}

	appPath := defaults.AppPath
	if resolvedScope == model.ScanScopeApp {
		appPath, err = prompter.promptLine(reader, fmt.Sprintf("App path to inspect (default %s): ", strings.TrimSpace(defaults.AppPath)))
		if err != nil {
			return SetupAnswers{}, err
		}
		if strings.TrimSpace(appPath) == "" {
			appPath = defaults.AppPath
		}
		if strings.TrimSpace(appPath) == "" {
			return SetupAnswers{}, fmt.Errorf("app path is required when scope=app")
		}
	}

	return SetupAnswers{
		Preset:   strings.TrimSpace(preset),
		OSFamily: strings.TrimSpace(osFamily),
		Scope:    resolvedScope,
		AppPath:  strings.TrimSpace(appPath),
	}, nil
}
