package discovery

import (
	"sync"

	"github.com/nagi1/larainspect/internal/model"
	"github.com/nagi1/larainspect/internal/rules"
)

var (
	defaultRuleEngineOnce sync.Once
	defaultRuleEngine     rules.Engine
)

func defaultFrameworkRuleEngine() rules.Engine {
	defaultRuleEngineOnce.Do(func() {
		engine, _ := rules.New(model.RuleConfig{})
		defaultRuleEngine = engine
	})

	return defaultRuleEngine
}
