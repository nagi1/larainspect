package correlators

import (
	"context"

	"github.com/nagi/larainspect/internal/model"
)

type Correlator interface {
	ID() string
	Correlate(context.Context, model.ExecutionContext, model.Snapshot, []model.Finding) (model.CheckResult, error)
}
