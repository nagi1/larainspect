package cli

import (
	"fmt"
	"io"

	"github.com/nagi1/larainspect/internal/baseline"
	"github.com/nagi1/larainspect/internal/model"
	"github.com/nagi1/larainspect/internal/store"
)

func runPostProcessing(stderr io.Writer, config model.AuditConfig, auditReport model.Report) {
	if stderr == nil {
		stderr = io.Discard
	}

	if updateBaselinePath := config.NormalizedUpdateBaselinePath(); updateBaselinePath != "" {
		if err := baseline.Save(updateBaselinePath, auditReport.Findings()); err != nil {
			fmt.Fprintf(stderr, "warning: unable to write baseline %s: %v\n", updateBaselinePath, err)
		}
	}

	if storeDir := config.NormalizedStoreDir(); storeDir != "" {
		historyStore := store.New(storeDir)
		if _, err := historyStore.Save(auditReport); err != nil {
			fmt.Fprintf(stderr, "warning: unable to persist scan history in %s: %v\n", storeDir, err)
		}
	}
}
