package testfixtures

import "testing"

func TestSampleReportBuilds(t *testing.T) {
	t.Parallel()

	report, err := SampleReport()
	if err != nil {
		t.Fatalf("SampleReport() error = %v", err)
	}

	if report.Summary.TotalFindings != 3 || report.Summary.CompromiseIndicators != 1 || report.Summary.Unknowns != 1 {
		t.Fatalf("unexpected sample report summary: %+v", report.Summary)
	}
}
