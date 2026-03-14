package progress

import (
	"sync"

	"github.com/nagi1/larainspect/internal/model"
)

type ComponentKind string

const (
	ComponentKindCheck      ComponentKind = "check"
	ComponentKindCorrelator ComponentKind = "correlator"
)

type ComponentStatus string

const (
	ComponentStatusPending   ComponentStatus = "pending"
	ComponentStatusRunning   ComponentStatus = "running"
	ComponentStatusCompleted ComponentStatus = "completed"
	ComponentStatusFailed    ComponentStatus = "failed"
)

type ComponentState struct {
	Kind        ComponentKind
	ID          string
	Description string
	Status      ComponentStatus
	Findings    int
	Unknowns    int
	Err         error
	Completed   int
	Total       int
}

type ContextSummary struct {
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
}

type Snapshot struct {
	CurrentStage        Stage
	Context             ContextSummary
	CheckTotal          int
	CheckCompleted      int
	CorrelatorTotal     int
	CorrelatorCompleted int
	FindingsDiscovered  int
	UnknownsObserved    int
	SeverityCounts      map[model.Severity]int
	Checks              []ComponentState
	Correlators         []ComponentState
	RecentEvents        []Event
}

type State struct {
	mu              sync.RWMutex
	maxRecentEvents int
	currentStage    Stage
	context         ContextSummary
	checkTotal      int
	checkCompleted  int
	correlatorTotal int
	correlatorDone  int
	findingsSeen    int
	unknownsSeen    int
	severityCounts  map[model.Severity]int
	checks          map[string]ComponentState
	checkOrder      []string
	correlators     map[string]ComponentState
	correlatorOrder []string
	recentEvents    []Event
}

func NewState(maxRecentEvents int) *State {
	if maxRecentEvents <= 0 {
		maxRecentEvents = 50
	}

	return &State{
		maxRecentEvents: maxRecentEvents,
		severityCounts: map[model.Severity]int{
			model.SeverityCritical:      0,
			model.SeverityHigh:          0,
			model.SeverityMedium:        0,
			model.SeverityLow:           0,
			model.SeverityInformational: 0,
		},
		checks:       map[string]ComponentState{},
		correlators:  map[string]ComponentState{},
		recentEvents: make([]Event, 0, maxRecentEvents),
	}
}

func (state *State) Handle(event Event) {
	if state == nil {
		return
	}

	state.mu.Lock()
	defer state.mu.Unlock()

	state.apply(event)
}

func (state *State) Snapshot() Snapshot {
	if state == nil {
		return Snapshot{}
	}

	state.mu.RLock()
	defer state.mu.RUnlock()

	snapshot := Snapshot{
		CurrentStage:        state.currentStage,
		Context:             state.context,
		CheckTotal:          state.checkTotal,
		CheckCompleted:      state.checkCompleted,
		CorrelatorTotal:     state.correlatorTotal,
		CorrelatorCompleted: state.correlatorDone,
		FindingsDiscovered:  state.findingsSeen,
		UnknownsObserved:    state.unknownsSeen,
		SeverityCounts:      cloneSeverityCounts(state.severityCounts),
		Checks:              make([]ComponentState, 0, len(state.checkOrder)),
		Correlators:         make([]ComponentState, 0, len(state.correlatorOrder)),
		RecentEvents:        append([]Event(nil), state.recentEvents...),
	}

	for _, id := range state.checkOrder {
		snapshot.Checks = append(snapshot.Checks, state.checks[id])
	}
	for _, id := range state.correlatorOrder {
		snapshot.Correlators = append(snapshot.Correlators, state.correlators[id])
	}

	return snapshot
}

func (state *State) apply(event Event) {
	state.recentEvents = append(state.recentEvents, event)
	if len(state.recentEvents) > state.maxRecentEvents {
		state.recentEvents = state.recentEvents[len(state.recentEvents)-state.maxRecentEvents:]
	}

	switch event.Type {
	case EventStageStarted:
		state.currentStage = event.Stage
	case EventContextResolved:
		state.context = ContextSummary{
			AppCount:       event.AppCount,
			AppName:        event.AppName,
			AppPath:        event.AppPath,
			LaravelVersion: event.LaravelVersion,
			PHPVersion:     event.PHPVersion,
			PackageCount:   event.PackageCount,
			ArtifactCount:  event.ArtifactCount,
			SourceMatches:  event.SourceMatches,
			NginxSites:     event.NginxSites,
			PHPFPMPools:    event.PHPFPMPools,
			Listeners:      event.Listeners,
		}
	case EventCheckRegistered:
		state.trackComponent(ComponentKindCheck, event.ComponentID, ComponentStatusPending, event)
	case EventCheckStarted:
		state.trackComponent(ComponentKindCheck, event.ComponentID, ComponentStatusRunning, event)
	case EventCheckCompleted:
		state.trackComponent(ComponentKindCheck, event.ComponentID, ComponentStatusCompleted, event)
		state.checkCompleted = maxInt(state.checkCompleted, event.Completed)
	case EventCheckFailed:
		state.trackComponent(ComponentKindCheck, event.ComponentID, ComponentStatusFailed, event)
		state.checkCompleted = maxInt(state.checkCompleted, event.Completed)
	case EventCorrelatorRegistered:
		state.trackComponent(ComponentKindCorrelator, event.ComponentID, ComponentStatusPending, event)
	case EventCorrelatorStarted:
		state.trackComponent(ComponentKindCorrelator, event.ComponentID, ComponentStatusRunning, event)
	case EventCorrelatorCompleted:
		state.trackComponent(ComponentKindCorrelator, event.ComponentID, ComponentStatusCompleted, event)
		state.correlatorDone = maxInt(state.correlatorDone, event.Completed)
	case EventCorrelatorFailed:
		state.trackComponent(ComponentKindCorrelator, event.ComponentID, ComponentStatusFailed, event)
		state.correlatorDone = maxInt(state.correlatorDone, event.Completed)
	case EventFindingDiscovered:
		state.findingsSeen++
		if _, exists := state.severityCounts[event.Severity]; exists {
			state.severityCounts[event.Severity]++
		}
	case EventUnknownObserved:
		state.unknownsSeen++
	}
}

func (state *State) trackComponent(kind ComponentKind, id string, status ComponentStatus, event Event) {
	if id == "" {
		id = "unknown"
	}

	switch kind {
	case ComponentKindCheck:
		component, exists := state.checks[id]
		if !exists {
			component = ComponentState{Kind: kind, ID: id}
			state.checkOrder = append(state.checkOrder, id)
		}
		if event.Message != "" {
			component.Description = event.Message
		}
		component.Status = status
		component.Findings = event.Findings
		component.Unknowns = event.Unknowns
		component.Err = event.Err
		component.Completed = event.Completed
		component.Total = event.Total
		state.checks[id] = component
		state.checkTotal = maxInt(state.checkTotal, event.Total)
	case ComponentKindCorrelator:
		component, exists := state.correlators[id]
		if !exists {
			component = ComponentState{Kind: kind, ID: id}
			state.correlatorOrder = append(state.correlatorOrder, id)
		}
		if event.Message != "" {
			component.Description = event.Message
		}
		component.Status = status
		component.Findings = event.Findings
		component.Unknowns = event.Unknowns
		component.Err = event.Err
		component.Completed = event.Completed
		component.Total = event.Total
		state.correlators[id] = component
		state.correlatorTotal = maxInt(state.correlatorTotal, event.Total)
	}
}

func maxInt(left int, right int) int {
	if right > left {
		return right
	}

	return left
}

func cloneSeverityCounts(counts map[model.Severity]int) map[model.Severity]int {
	if len(counts) == 0 {
		return map[model.Severity]int{}
	}

	clonedCounts := make(map[model.Severity]int, len(counts))
	for severity, count := range counts {
		clonedCounts[severity] = count
	}

	return clonedCounts
}
