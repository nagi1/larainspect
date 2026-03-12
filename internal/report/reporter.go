package report

import (
	"io"

	"github.com/nagi/larainspect/internal/model"
)

type Reporter interface {
	Format() string
	Render(io.Writer, model.Report) error
}
