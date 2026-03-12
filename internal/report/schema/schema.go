package schema

import "github.com/nagi/larainspect/internal/model"

type Document = model.Report

func FromReport(report model.Report) Document {
	return Document(report)
}
