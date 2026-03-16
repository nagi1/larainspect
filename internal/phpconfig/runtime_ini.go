package phpconfig

import (
	"fmt"
	"strings"

	"github.com/nagi1/larainspect/internal/model"
	ini "gopkg.in/ini.v1"
)

func ParseRuntimeINI(configPath string, contents string) (model.PHPINIConfig, error) {
	config, err := ini.LoadSources(ini.LoadOptions{
		IgnoreInlineComment:       false,
		SpaceBeforeInlineComment:  true,
		SkipUnrecognizableLines:   true,
		UnescapeValueDoubleQuotes: true,
		KeyValueDelimiters:        "=",
	}, []byte(contents))
	if err != nil {
		return model.PHPINIConfig{}, fmt.Errorf("parse php.ini config %s: %w", configPath, err)
	}

	runtimeConfig := model.PHPINIConfig{ConfigPath: configPath}
	for _, section := range config.Sections() {
		applyRuntimeINISection(&runtimeConfig, section)
	}

	return runtimeConfig, nil
}

func applyRuntimeINISection(runtimeConfig *model.PHPINIConfig, section *ini.Section) {
	for _, key := range section.Keys() {
		switch strings.ToLower(strings.TrimSpace(key.Name())) {
		case "cgi.fix_pathinfo":
			runtimeConfig.CGIFixPathinfo = cleanValue(key.String())
		case "expose_php":
			runtimeConfig.ExposePHP = cleanValue(key.String())
		}
	}
}
