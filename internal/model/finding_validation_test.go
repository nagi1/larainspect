package model_test

import (
	"testing"
	"time"

	"github.com/nagi1/larainspect/internal/model"
)

func TestSeverityConfidenceClassAndErrorKindValidation(t *testing.T) {
	t.Parallel()

	if model.Severity("bad").Valid() {
		t.Fatal("expected invalid severity to be rejected")
	}
	if model.Confidence("bad").Valid() {
		t.Fatal("expected invalid confidence to be rejected")
	}
	if model.FindingClass("bad").Valid() {
		t.Fatal("expected invalid finding class to be rejected")
	}
	if model.ErrorKind("bad").Valid() {
		t.Fatal("expected invalid error kind to be rejected")
	}
}

func TestFindingValidateRejectsInvalidFields(t *testing.T) {
	t.Parallel()

	testCases := []model.Finding{
		{},
		{ID: "id"},
		{ID: "id", CheckID: "check"},
		{ID: "id", CheckID: "check", Title: "title"},
		{ID: "id", CheckID: "check", Title: "title", Why: "why"},
		{ID: "id", CheckID: "check", Title: "title", Why: "why", Remediation: "fix", Class: "bad", Severity: model.SeverityHigh, Confidence: model.ConfidenceConfirmed, Evidence: []model.Evidence{{Label: "l", Detail: "d"}}},
		{ID: "id", CheckID: "check", Title: "title", Why: "why", Remediation: "fix", Class: model.FindingClassDirect, Severity: "bad", Confidence: model.ConfidenceConfirmed, Evidence: []model.Evidence{{Label: "l", Detail: "d"}}},
		{ID: "id", CheckID: "check", Title: "title", Why: "why", Remediation: "fix", Class: model.FindingClassDirect, Severity: model.SeverityHigh, Confidence: "bad", Evidence: []model.Evidence{{Label: "l", Detail: "d"}}},
		{ID: "id", CheckID: "check", Title: "title", Why: "why", Remediation: "fix", Class: model.FindingClassDirect, Severity: model.SeverityHigh, Confidence: model.ConfidenceConfirmed},
	}

	for _, finding := range testCases {
		if err := finding.Validate(); err == nil {
			t.Fatalf("expected validation error for finding %+v", finding)
		}
	}
}

func TestUnknownValidateRejectsInvalidFields(t *testing.T) {
	t.Parallel()

	testCases := []model.Unknown{
		{},
		{ID: "id"},
		{ID: "id", CheckID: "check"},
		{ID: "id", CheckID: "check", Title: "title"},
		{ID: "id", CheckID: "check", Title: "title", Reason: "why"},
		{ID: "id", CheckID: "check", Title: "title", Reason: "why", Error: "bad"},
	}

	for _, unknown := range testCases {
		if err := unknown.Validate(); err == nil {
			t.Fatalf("expected validation error for unknown %+v", unknown)
		}
	}
}

func TestBuildReportRejectsInvalidPayloads(t *testing.T) {
	t.Parallel()

	_, err := model.BuildReport(model.Host{}, time.Now(), time.Second, []model.Finding{{}}, nil)
	if err == nil {
		t.Fatal("expected invalid finding error")
	}

	validFinding := model.Finding{
		ID:          "id",
		CheckID:     "check",
		Class:       model.FindingClassDirect,
		Severity:    model.SeverityLow,
		Confidence:  model.ConfidenceConfirmed,
		Title:       "title",
		Why:         "why",
		Remediation: "fix",
		Evidence:    []model.Evidence{{Label: "label", Detail: "detail"}},
	}
	_, err = model.BuildReport(model.Host{}, time.Now(), time.Second, []model.Finding{validFinding}, []model.Unknown{{}})
	if err == nil {
		t.Fatal("expected invalid unknown error")
	}
}
