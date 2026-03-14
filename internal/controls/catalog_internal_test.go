package controls

import "testing"

func TestEvidenceTypeValidRejectsUnknown(t *testing.T) {
	t.Parallel()

	if EvidenceType("unknown").Valid() {
		t.Fatal("expected unknown evidence type to be invalid")
	}
}

func TestValidateControlReportsInvalidMetadata(t *testing.T) {
	t.Parallel()

	seenControlIDs := map[string]struct{}{}
	registeredChecks := map[string]struct{}{
		"known.check": {},
	}

	issues := validateControl(Control{
		ID:           "demo",
		Status:       Status("bad"),
		EvidenceType: EvidenceType("bad"),
		CheckIDs:     []string{"unknown.check"},
		Sources: []Source{
			{Category: "demo", Title: "Demo"},
		},
	}, seenControlIDs, registeredChecks)

	if len(issues) != 4 {
		t.Fatalf("expected invalid metadata issues, got %v", issues)
	}

	outOfScopeIssues := validateControl(Control{
		ID:           "out-of-scope",
		Status:       StatusOutOfScope,
		EvidenceType: EvidenceOutOfScope,
		Sources: []Source{
			{Category: "demo", Title: "Demo", URL: "https://example.com"},
		},
	}, seenControlIDs, registeredChecks)

	if len(outOfScopeIssues) != 1 {
		t.Fatalf("expected missing reason issue, got %v", outOfScopeIssues)
	}

	duplicateIssues := validateControl(Control{
		ID:           "demo",
		Status:       StatusImplemented,
		EvidenceType: EvidenceHostConfig,
		Sources: []Source{
			{Category: "demo", Title: "Demo", URL: "https://example.com"},
		},
	}, seenControlIDs, registeredChecks)

	if len(duplicateIssues) != 1 {
		t.Fatalf("expected duplicate id issue, got %v", duplicateIssues)
	}
}
