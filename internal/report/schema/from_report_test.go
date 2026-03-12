package schema_test

import (
	"testing"
	"time"

	"github.com/nagi1/larainspect/internal/model"
	"github.com/nagi1/larainspect/internal/report/schema"
)

func TestFromReportReturnsDocument(t *testing.T) {
	t.Parallel()

	report, err := model.BuildReport(model.Host{Hostname: "demo"}, time.Now(), time.Second, nil, nil)
	if err != nil {
		t.Fatalf("BuildReport() error = %v", err)
	}

	document := schema.FromReport(report)
	if document.SchemaVersion != model.SchemaVersion {
		t.Fatalf("unexpected schema version %q", document.SchemaVersion)
	}
}
