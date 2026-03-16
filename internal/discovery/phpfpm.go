package discovery

import (
	"github.com/nagi1/larainspect/internal/model"
	"github.com/nagi1/larainspect/internal/phpconfig"
)

func parsePHPFPMPools(configPath string, contents string) ([]model.PHPFPMPool, error) {
	return phpconfig.ParsePools(configPath, contents)
}
