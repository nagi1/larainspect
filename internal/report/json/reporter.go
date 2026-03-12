package json

import (
	"encoding/json"
	"io"

	"github.com/nagi1/larainspect/internal/model"
	"github.com/nagi1/larainspect/internal/report/schema"
)

type Reporter struct{}

func NewReporter() Reporter {
	return Reporter{}
}

func (reporter Reporter) Format() string {
	return "json"
}

func (reporter Reporter) Render(writer io.Writer, report model.Report) error {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")

	return encoder.Encode(schema.FromReport(report))
}
