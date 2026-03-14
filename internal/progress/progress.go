package progress

import (
	"sync"
	"time"

	"github.com/nagi1/larainspect/internal/model"
)

type EventType string

const (
	EventAuditStarted         EventType = "audit.started"
	EventAuditCompleted       EventType = "audit.completed"
	EventAuditFailed          EventType = "audit.failed"
	EventStageStarted         EventType = "stage.started"
	EventStageCompleted       EventType = "stage.completed"
	EventContextResolved      EventType = "context.resolved"
	EventCheckRegistered      EventType = "check.registered"
	EventCheckStarted         EventType = "check.started"
	EventCheckCompleted       EventType = "check.completed"
	EventCheckFailed          EventType = "check.failed"
	EventFindingDiscovered    EventType = "finding.discovered"
	EventUnknownObserved      EventType = "unknown.observed"
	EventCorrelatorRegistered EventType = "correlator.registered"
	EventCorrelatorStarted    EventType = "correlator.started"
	EventCorrelatorCompleted  EventType = "correlator.completed"
	EventCorrelatorFailed     EventType = "correlator.failed"
)

type Stage string

const (
	StageSetup       Stage = "setup"
	StageDiscovery   Stage = "discovery"
	StageChecks      Stage = "checks"
	StageCorrelation Stage = "correlation"
	StagePostProcess Stage = "post_process"
	StageReport      Stage = "report"
)

func (stage Stage) Label() string {
	switch stage {
	case StageSetup:
		return "Setup"
	case StageDiscovery:
		return "Discovery"
	case StageChecks:
		return "Checks"
	case StageCorrelation:
		return "Correlation"
	case StagePostProcess:
		return "Post-Process"
	case StageReport:
		return "Report"
	default:
		return string(stage)
	}
}

func OrderedStages() []Stage {
	return []Stage{
		StageSetup,
		StageDiscovery,
		StageChecks,
		StageCorrelation,
		StagePostProcess,
		StageReport,
	}
}

type Event struct {
	Type           EventType
	Stage          Stage
	At             time.Time
	ComponentID    string
	Message        string
	AppCount       int
	AppName        string
	AppPath        string
	LaravelVersion string
	PHPVersion     string
	PackageCount   int
	ArtifactCount  int
	SourceMatches  int
	NginxSites     int
	PHPFPMPools    int
	Listeners      int
	Completed      int
	Total          int
	Findings       int
	Unknowns       int
	Severity       model.Severity
	Class          model.FindingClass
	ErrorKind      model.ErrorKind
	Title          string
	Err            error
}

func NewEvent(eventType EventType) Event {
	return Event{
		Type: eventType,
		At:   time.Now().UTC(),
	}
}

type Handler func(Event)

type Bus struct {
	mu          sync.RWMutex
	subscribers map[EventType][]Handler
	allHandlers []Handler
	closed      bool
}

func NewBus() *Bus {
	return &Bus{
		subscribers: map[EventType][]Handler{},
	}
}

func (bus *Bus) Subscribe(eventType EventType, handler Handler) {
	if bus == nil || handler == nil {
		return
	}

	bus.mu.Lock()
	defer bus.mu.Unlock()

	bus.subscribers[eventType] = append(bus.subscribers[eventType], handler)
}

func (bus *Bus) SubscribeAll(handler Handler) {
	if bus == nil || handler == nil {
		return
	}

	bus.mu.Lock()
	defer bus.mu.Unlock()

	bus.allHandlers = append(bus.allHandlers, handler)
}

func (bus *Bus) Publish(event Event) {
	if bus == nil {
		return
	}

	bus.mu.Lock()
	defer bus.mu.Unlock()

	if bus.closed {
		return
	}

	for _, handler := range bus.allHandlers {
		handler(event)
	}

	for _, handler := range bus.subscribers[event.Type] {
		handler(event)
	}
}

func (bus *Bus) Close() {
	if bus == nil {
		return
	}

	bus.mu.Lock()
	defer bus.mu.Unlock()

	bus.closed = true
}
