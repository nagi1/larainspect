package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nagi1/larainspect/internal/baseline"
	"github.com/nagi1/larainspect/internal/model"
	"github.com/nagi1/larainspect/internal/store"
)

func TestRunPostProcessingPersistsBaselineAndHistory(t *testing.T) {

	report, err := model.BuildReport(
		model.Host{Hostname: "prod-web-01"},
		time.Unix(1700000000, 0),
		time.Second,
		[]model.Finding{{
			ID:          "demo.finding",
			CheckID:     "demo.check",
			Class:       model.FindingClassDirect,
			Severity:    model.SeverityHigh,
			Confidence:  model.ConfidenceConfirmed,
			Title:       "Demo finding",
			Why:         "demo why",
			Remediation: "demo remediation",
			Evidence:    []model.Evidence{{Label: "demo", Detail: "value"}},
		}},
		nil,
	)
	if err != nil {
		t.Fatalf("BuildReport() error = %v", err)
	}

	baselinePath := filepath.Join(t.TempDir(), "baseline.json")
	storeDir := filepath.Join(t.TempDir(), "store")
	runPostProcessing(&bytes.Buffer{}, model.AuditConfig{
		UpdateBaselinePath: baselinePath,
		StoreDir:           storeDir,
	}, report)

	loadedBaseline, err := baseline.Load(baselinePath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if loadedBaseline == nil || len(loadedBaseline.Entries) != 1 {
		t.Fatalf("expected saved baseline entry, got %+v", loadedBaseline)
	}

	records, err := store.New(storeDir).ListRecords()
	if err != nil {
		t.Fatalf("ListRecords() error = %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected one stored record, got %+v", records)
	}
}

func TestRunPostProcessingWarnsOnPersistenceFailures(t *testing.T) {

	report, err := model.BuildReport(model.Host{}, time.Unix(1700000000, 0), time.Second, nil, nil)
	if err != nil {
		t.Fatalf("BuildReport() error = %v", err)
	}

	baseDir := t.TempDir()
	blockingPath := filepath.Join(baseDir, "blocking-file")
	if err := os.WriteFile(blockingPath, []byte("nope"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	var stderr bytes.Buffer
	runPostProcessing(&stderr, model.AuditConfig{
		UpdateBaselinePath: filepath.Join(blockingPath, "baseline.json"),
		StoreDir:           filepath.Join(blockingPath, "store"),
	}, report)

	for _, want := range []string{
		"warning: unable to write baseline",
		"warning: unable to persist scan history",
	} {
		if !bytes.Contains(stderr.Bytes(), []byte(want)) {
			t.Fatalf("expected stderr to contain %q, got %q", want, stderr.String())
		}
	}
}
