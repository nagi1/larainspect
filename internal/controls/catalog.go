package controls

import (
	"slices"
	"strings"
)

type Status string

const (
	StatusImplemented Status = "implemented"
	StatusPartial     Status = "partial"
	StatusQueued      Status = "queued"
	StatusOutOfScope  Status = "out_of_scope"
)

func (status Status) Valid() bool {
	switch status {
	case StatusImplemented, StatusPartial, StatusQueued, StatusOutOfScope:
		return true
	default:
		return false
	}
}

type EvidenceType string

const (
	EvidenceHostPath   EvidenceType = "host_path_metadata"
	EvidenceHostConfig EvidenceType = "host_service_config"
	EvidenceSourceCode EvidenceType = "application_source_rules"
	EvidenceHybrid     EvidenceType = "hybrid_host_and_source"
	EvidencePolicyOnly EvidenceType = "policy_only"
	EvidenceOutOfScope EvidenceType = "out_of_scope"
)

func (evidenceType EvidenceType) Valid() bool {
	switch evidenceType {
	case EvidenceHostPath, EvidenceHostConfig, EvidenceSourceCode, EvidenceHybrid, EvidencePolicyOnly, EvidenceOutOfScope:
		return true
	default:
		return false
	}
}

type Source struct {
	Category string `json:"category"`
	Title    string `json:"title"`
	URL      string `json:"url"`
}

type Control struct {
	ID               string       `json:"id"`
	Name             string       `json:"name"`
	SourceCategories []string     `json:"source_categories"`
	Sources          []Source     `json:"sources"`
	Description      string       `json:"description"`
	EvidenceType     EvidenceType `json:"evidence_type"`
	Status           Status       `json:"status"`
	CheckIDs         []string     `json:"check_ids,omitempty"`
	MissingWork      string       `json:"missing_work,omitempty"`
	OutOfScopeReason string       `json:"out_of_scope_reason,omitempty"`

	matches []match
}

type match struct {
	CheckID       string
	FindingPrefix string
}

var catalog = buildCatalog()

func All() []Control {
	cloned := make([]Control, len(catalog))
	copy(cloned, catalog)
	return cloned
}

func ByID(controlID string) (Control, bool) {
	for _, control := range catalog {
		if control.ID == controlID {
			return control, true
		}
	}

	return Control{}, false
}

func ForCheckID(checkID string) []Control {
	matches := []Control{}
	for _, control := range catalog {
		if control.coversCheck(checkID) {
			matches = append(matches, control)
		}
	}

	return matches
}

func ForFinding(checkID string, findingID string) []Control {
	prefixMatches := []Control{}
	checkMatches := []Control{}

	for _, control := range catalog {
		if !control.coversCheck(checkID) {
			continue
		}

		if control.matchesFinding(checkID, findingID) {
			prefixMatches = append(prefixMatches, control)
			continue
		}

		checkMatches = append(checkMatches, control)
	}

	if len(prefixMatches) > 0 {
		return prefixMatches
	}

	return checkMatches
}

func Filter(statuses []Status, checkIDs []string) []Control {
	statusSet := makeStatusSet(statuses)
	checkSet := makeCheckSet(checkIDs)
	filtered := []Control{}

	for _, control := range catalog {
		if len(statusSet) > 0 {
			if _, found := statusSet[control.Status]; !found {
				continue
			}
		}

		if len(checkSet) > 0 && !control.matchesAnyCheck(checkSet) {
			continue
		}

		filtered = append(filtered, control)
	}

	return filtered
}

func NormalizeStatus(value string) (Status, bool) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	normalized = strings.ReplaceAll(normalized, "-", "_")

	status := Status(normalized)
	return status, status.Valid()
}

func ValidateCatalog(registeredCheckIDs []string) []string {
	issues := []string{}
	seenControlIDs := map[string]struct{}{}
	registeredChecks := makeCheckSet(registeredCheckIDs)

	for _, control := range catalog {
		issues = append(issues, validateControl(control, seenControlIDs, registeredChecks)...)
	}

	return issues
}

func SortedStatuses() []Status {
	return []Status{
		StatusImplemented,
		StatusPartial,
		StatusQueued,
		StatusOutOfScope,
	}
}

func SortByID(controls []Control) {
	slices.SortFunc(controls, func(left Control, right Control) int {
		return strings.Compare(left.ID, right.ID)
	})
}

func buildCatalog() []Control {
	controls := []Control{}
	controls = append(controls, applicationControls()...)
	controls = append(controls, runtimeControls()...)
	controls = append(controls, operationsControls()...)
	controls = append(controls, scopeBoundaryControls()...)

	return finalizeControls(controls)
}

func finalizeControls(controls []Control) []Control {
	for index := range controls {
		controls[index].CheckIDs = uniqueCheckIDs(controls[index].matches)
		controls[index].SourceCategories = uniqueSourceCategories(controls[index].Sources)
	}

	return controls
}

func validateControl(control Control, seenControlIDs map[string]struct{}, registeredChecks map[string]struct{}) []string {
	issues := []string{}

	if strings.TrimSpace(control.ID) == "" {
		issues = append(issues, "control id is required")
	}
	if _, found := seenControlIDs[control.ID]; found {
		issues = append(issues, "duplicate control id: "+control.ID)
	}
	seenControlIDs[control.ID] = struct{}{}

	if !control.Status.Valid() {
		issues = append(issues, "invalid status for control: "+control.ID)
	}
	if !control.EvidenceType.Valid() {
		issues = append(issues, "invalid evidence type for control: "+control.ID)
	}
	if len(control.Sources) == 0 {
		issues = append(issues, "missing sources for control: "+control.ID)
	}

	for _, source := range control.Sources {
		if strings.TrimSpace(source.URL) == "" {
			issues = append(issues, "source URL is required for control: "+control.ID)
		}
	}

	for _, checkID := range control.CheckIDs {
		if _, found := registeredChecks[checkID]; !found {
			issues = append(issues, "unknown check id "+checkID+" for control "+control.ID)
		}
	}

	if control.Status == StatusOutOfScope && strings.TrimSpace(control.OutOfScopeReason) == "" {
		issues = append(issues, "out_of_scope control missing reason: "+control.ID)
	}

	return issues
}

func makeStatusSet(statuses []Status) map[Status]struct{} {
	statusSet := map[Status]struct{}{}
	for _, status := range statuses {
		statusSet[status] = struct{}{}
	}

	return statusSet
}

func makeCheckSet(checkIDs []string) map[string]struct{} {
	checkSet := map[string]struct{}{}
	for _, checkID := range checkIDs {
		trimmed := strings.TrimSpace(checkID)
		if trimmed == "" {
			continue
		}
		checkSet[trimmed] = struct{}{}
	}

	return checkSet
}

func (control Control) coversCheck(checkID string) bool {
	for _, candidate := range control.CheckIDs {
		if candidate == checkID {
			return true
		}
	}

	return false
}

func (control Control) matchesFinding(checkID string, findingID string) bool {
	for _, selector := range control.matches {
		if selector.CheckID != "" && selector.CheckID != checkID {
			continue
		}
		if selector.FindingPrefix == "" {
			continue
		}
		if strings.HasPrefix(findingID, selector.FindingPrefix) {
			return true
		}
	}

	return false
}

func (control Control) matchesAnyCheck(checkSet map[string]struct{}) bool {
	for _, checkID := range control.CheckIDs {
		if _, found := checkSet[checkID]; found {
			return true
		}
	}

	return false
}

func source(category string, title string, url string) Source {
	return Source{Category: category, Title: title, URL: url}
}

func mapping(checkID string, findingPrefix string) match {
	return match{CheckID: checkID, FindingPrefix: findingPrefix}
}

func uniqueCheckIDs(matches []match) []string {
	checkIDs := make([]string, 0, len(matches))
	seen := map[string]struct{}{}

	for _, selector := range matches {
		if selector.CheckID == "" {
			continue
		}
		if _, found := seen[selector.CheckID]; found {
			continue
		}
		seen[selector.CheckID] = struct{}{}
		checkIDs = append(checkIDs, selector.CheckID)
	}

	return checkIDs
}

func uniqueSourceCategories(sources []Source) []string {
	categories := make([]string, 0, len(sources))
	seen := map[string]struct{}{}

	for _, source := range sources {
		category := strings.TrimSpace(source.Category)
		if category == "" {
			continue
		}
		if _, found := seen[category]; found {
			continue
		}
		seen[category] = struct{}{}
		categories = append(categories, category)
	}

	return categories
}
