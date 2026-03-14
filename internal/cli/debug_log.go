package cli

import (
	"fmt"

	"github.com/nagi1/larainspect/internal/debuglog"
	"github.com/nagi1/larainspect/internal/model"
	"github.com/nagi1/larainspect/internal/progress"
)

func openDebugLogger(config model.AuditConfig) (*debuglog.Logger, func(), error) {
	path := config.NormalizedDebugLogPath()
	if path == "" {
		return nil, func() {}, nil
	}

	logger, closer, err := debuglog.OpenFile(path)
	if err != nil {
		return nil, func() {}, fmt.Errorf("open debug log %q: %w", path, err)
	}

	return logger, func() {
		if closer != nil {
			_ = closer.Close()
		}
	}, nil
}

func attachDebugLogger(bus *progress.Bus, logger *debuglog.Logger) {
	if bus != nil && logger != nil {
		bus.SubscribeAll(logger.LogProgressEvent)
	}
}
