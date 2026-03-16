package discovery

import (
	"github.com/nagi1/larainspect/internal/model"
	"github.com/nagi1/larainspect/internal/phpconfig"
)

func parsePHPINIConfig(configPath string, contents string) (model.PHPINIConfig, error) {
	return phpconfig.ParseRuntimeINI(configPath, contents)
}
