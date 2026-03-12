package discovery

import (
	"context"

	"github.com/nagi/larainspect/internal/model"
)

type Service interface {
	Discover(context.Context, model.ExecutionContext) (model.Snapshot, []model.Unknown, error)
}

type NoopService struct{}

func (service NoopService) Discover(_ context.Context, execution model.ExecutionContext) (model.Snapshot, []model.Unknown, error) {
	return model.Snapshot{
		Host:  execution.Host,
		Tools: execution.Tools,
	}, nil, nil
}
