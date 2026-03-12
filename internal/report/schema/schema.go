package schema

import (
	_ "embed"

	"github.com/nagi/larainspect/internal/model"
)

//go:embed report.schema.json
var draft []byte

type Document = model.Report

func FromReport(report model.Report) Document {
	return Document(report)
}

func Draft() []byte {
	copied := make([]byte, len(draft))
	copy(copied, draft)
	return copied
}

func DraftVersion() string {
	return model.SchemaVersion
}
