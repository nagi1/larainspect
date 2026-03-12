package ux

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/nagi/larainspect/internal/model"
)

type Prompter struct {
	Input  io.Reader
	Output io.Writer
}

func (prompter Prompter) ResolveAuditConfig(config model.AuditConfig) (model.AuditConfig, error) {
	if !config.Interactive {
		return config, nil
	}

	reader := bufio.NewReader(prompter.Input)

	fmt.Fprintln(prompter.Output, "Guided mode is enabled. Press Enter to keep the default in brackets.")

	if config.Scope == model.ScanScopeAuto {
		scope, err := prompter.promptScope(reader, config.Scope)
		if err != nil {
			return config, err
		}
		config.Scope = scope
	}

	if config.Scope == model.ScanScopeApp && strings.TrimSpace(config.AppPath) == "" {
		appPath, err := prompter.promptAppPath(reader)
		if err != nil {
			return config, err
		}
		config.AppPath = appPath
	}

	return config, nil
}

func (prompter Prompter) promptScope(reader *bufio.Reader, defaultScope model.ScanScope) (model.ScanScope, error) {
	response, err := prompter.promptLine(reader, fmt.Sprintf("Audit scope [%s/%s/%s] (default %s): ", model.ScanScopeAuto, model.ScanScopeHost, model.ScanScopeApp, defaultScope))
	if err != nil {
		return defaultScope, err
	}

	if strings.TrimSpace(response) == "" {
		return defaultScope, nil
	}

	scope := model.ScanScope(strings.ToLower(strings.TrimSpace(response)))
	if !scope.Valid() {
		return "", fmt.Errorf("invalid interactive scope %q", response)
	}

	return scope, nil
}

func (prompter Prompter) promptAppPath(reader *bufio.Reader) (string, error) {
	response, err := prompter.promptLine(reader, "App path to inspect: ")
	if err != nil {
		return "", err
	}

	if strings.TrimSpace(response) == "" {
		return "", fmt.Errorf("app path is required when scope=app")
	}

	return strings.TrimSpace(response), nil
}

func (prompter Prompter) promptLine(reader *bufio.Reader, label string) (string, error) {
	if _, err := fmt.Fprint(prompter.Output, label); err != nil {
		return "", err
	}

	line, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}

	return strings.TrimSpace(line), nil
}
