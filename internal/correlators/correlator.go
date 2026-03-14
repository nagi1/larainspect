package correlators

import (
	"context"

	"github.com/nagi1/larainspect/internal/model"
)

type Correlator interface {
	ID() string
	Description() string
	Correlate(context.Context, model.ExecutionContext, model.Snapshot, []model.Finding) (model.CheckResult, error)
}
