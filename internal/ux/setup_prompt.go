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

type IdentityAnswers struct {
	DeployUsers   []string
	RuntimeUsers  []string
	RuntimeGroups []string
	WebUsers      []string
	WebGroups     []string
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

func (prompter Prompter) ResolveIdentityAnswers(defaults IdentityAnswers) (IdentityAnswers, error) {
	reader := bufio.NewReader(prompter.Input)

	if _, err := fmt.Fprintln(prompter.Output, "Could not confidently detect all deploy, runtime, and web identities. Review the missing values Larainspect should enforce."); err != nil {
		return IdentityAnswers{}, err
	}

	resolved := defaults
	var err error
	if len(resolved.DeployUsers) == 0 {
		resolved.DeployUsers, err = prompter.promptIdentityList(reader, "Deploy users")
		if err != nil {
			return IdentityAnswers{}, err
		}
	}
	if len(resolved.RuntimeUsers) == 0 {
		resolved.RuntimeUsers, err = prompter.promptIdentityList(reader, "Runtime users")
		if err != nil {
			return IdentityAnswers{}, err
		}
	}
	if len(resolved.RuntimeGroups) == 0 {
		resolved.RuntimeGroups, err = prompter.promptIdentityList(reader, "Runtime groups")
		if err != nil {
			return IdentityAnswers{}, err
		}
	}
	if len(resolved.WebUsers) == 0 {
		resolved.WebUsers, err = prompter.promptIdentityList(reader, "Web users")
		if err != nil {
			return IdentityAnswers{}, err
		}
	}
	if len(resolved.WebGroups) == 0 {
		resolved.WebGroups, err = prompter.promptIdentityList(reader, "Web groups")
		if err != nil {
			return IdentityAnswers{}, err
		}
	}

	return resolved, nil
}

func (prompter Prompter) promptIdentityList(reader *bufio.Reader, label string) ([]string, error) {
	response, err := prompter.promptLine(reader, fmt.Sprintf("%s (comma-separated, leave blank to skip): ", label))
	if err != nil {
		return nil, err
	}

	return splitIdentityList(response), nil
}

func splitIdentityList(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}

	parts := strings.Split(raw, ",")
	values := make([]string, 0, len(parts))
	seen := map[string]struct{}{}
	for _, part := range parts {
		trimmedPart := strings.TrimSpace(part)
		if trimmedPart == "" {
			continue
		}

		lookupKey := strings.ToLower(trimmedPart)
		if _, found := seen[lookupKey]; found {
			continue
		}

		seen[lookupKey] = struct{}{}
		values = append(values, trimmedPart)
	}

	if len(values) == 0 {
		return nil
	}

	return values
}
