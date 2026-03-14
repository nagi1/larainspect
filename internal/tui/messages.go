package tui

import (
	"time"

	"github.com/nagi1/larainspect/internal/model"
)

// ViewID identifies which view is currently active.
type ViewID int

const (
	ViewScan ViewID = iota
	ViewResults
)

// switchViewMsg requests a view change.
type switchViewMsg struct {
	view ViewID
}

// ReportReadyMsg delivers the final audit report to the TUI event loop.
type ReportReadyMsg struct {
	Report model.Report
}

// tickMsg drives spinner and animation updates.
type tickMsg time.Time
