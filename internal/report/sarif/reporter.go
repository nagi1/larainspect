package sarif

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"

	"github.com/nagi1/larainspect/internal/model"
	"github.com/nagi1/larainspect/internal/report"
	"github.com/nagi1/larainspect/internal/report/reportfmt"
)

var _ report.Reporter = Reporter{}

// Reporter generates SARIF 2.1.0 output for GitHub Code Scanning and other
// static-analysis consumers.
type Reporter struct{}

func NewReporter() Reporter {
	return Reporter{}
}

func (r Reporter) Format() string {
	return "sarif"
}

func (r Reporter) Render(w io.Writer, report model.Report) error {
	allFindings := collectAllFindings(report)

	rules, ruleIndex := buildRules(allFindings)
	results := buildResults(allFindings, ruleIndex)

	doc := sarifDocument{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{
				Driver: sarifDriver{
					Name:           "Larainspect",
					InformationURI: "https://github.com/nagi1/larainspect",
					Version:        model.SchemaVersion,
					Rules:          rules,
				},
			},
			Results: results,
		}},
	}

	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(doc)
}

// collectAllFindings merges all finding classes into a single ordered slice.
func collectAllFindings(report model.Report) []model.Finding {
	total := len(report.DirectFindings) + len(report.HeuristicFindings) + len(report.CompromiseIndicators)
	all := make([]model.Finding, 0, total)
	all = append(all, report.DirectFindings...)
	all = append(all, report.HeuristicFindings...)
	all = append(all, report.CompromiseIndicators...)
	return all
}

func buildRules(findings []model.Finding) ([]sarifRule, map[string]int) {
	ruleIndex := make(map[string]int)
	var rules []sarifRule

	for _, f := range findings {
		if _, exists := ruleIndex[f.CheckID]; exists {
			continue
		}
		ruleIndex[f.CheckID] = len(rules)
		rules = append(rules, sarifRule{
			ID:               f.CheckID,
			Name:             f.Title,
			ShortDescription: sarifMessage{Text: f.Title},
			FullDescription:  sarifMessage{Text: f.Why},
			DefaultConfiguration: sarifRuleConfig{
				Level: severityToLevel(f.Severity),
			},
			Help: sarifMessage{Text: f.Remediation},
			Properties: sarifRuleProperties{
				Tags:     []string{string(f.Class)},
				Security: severityToSARIFSecurity(f.Severity),
			},
		})
	}

	return rules, ruleIndex
}

func buildResults(findings []model.Finding, ruleIndex map[string]int) []sarifResult {
	results := make([]sarifResult, 0, len(findings))

	for _, f := range findings {
		result := sarifResult{
			RuleID:    f.CheckID,
			RuleIndex: ruleIndex[f.CheckID],
			Level:     severityToLevel(f.Severity),
			Message:   sarifMessage{Text: f.Title},
			Properties: sarifResultProperties{
				FindingClass: string(f.Class),
				Confidence:   string(f.Confidence),
			},
		}

		// Build location from the first affected target with a path.
		if loc := locationFromFinding(f); loc != nil {
			result.Locations = []sarifLocation{*loc}
		}

		result.PartialFingerprints = map[string]string{
			"larainspect/v1": findingFingerprint(f),
		}

		results = append(results, result)
	}

	return results
}

func locationFromFinding(f model.Finding) *sarifLocation {
	for _, t := range f.Affected {
		path := t.Path
		if path == "" {
			path = t.Name
		}
		if path == "" {
			continue
		}
		return &sarifLocation{
			PhysicalLocation: sarifPhysicalLocation{
				ArtifactLocation: sarifArtifactLocation{URI: path},
				Region:           sarifRegion{StartLine: 1},
			},
		}
	}
	return nil
}

// findingFingerprint returns a stable hash for baseline/dedup use.
// Based on check_id + class + first affected target, so wording changes
// don't alter identity.
func findingFingerprint(f model.Finding) string {
	h := sha256.New()
	h.Write([]byte(f.CheckID))
	h.Write([]byte{':'})
	h.Write([]byte(f.Class))
	h.Write([]byte{':'})
	h.Write([]byte(f.ID))
	if len(f.Affected) > 0 {
		h.Write([]byte{':'})
		h.Write([]byte(reportfmt.DescribeTarget(f.Affected[0])))
	}
	return fmt.Sprintf("%x", h.Sum(nil))[:16]
}

func severityToLevel(s model.Severity) string {
	switch s {
	case model.SeverityCritical, model.SeverityHigh:
		return "error"
	case model.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

func severityToSARIFSecurity(s model.Severity) string {
	switch s {
	case model.SeverityCritical:
		return "critical"
	case model.SeverityHigh:
		return "high"
	case model.SeverityMedium:
		return "medium"
	case model.SeverityLow:
		return "low"
	default:
		return "informational"
	}
}

// SARIF 2.1.0 data structures

type sarifDocument struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool      `json:"tool"`
	Results []sarifResult  `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Version        string      `json:"version"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string              `json:"id"`
	Name                 string              `json:"name"`
	ShortDescription     sarifMessage        `json:"shortDescription"`
	FullDescription      sarifMessage        `json:"fullDescription"`
	DefaultConfiguration sarifRuleConfig     `json:"defaultConfiguration"`
	Help                 sarifMessage        `json:"help"`
	Properties           sarifRuleProperties `json:"properties"`
}

type sarifRuleConfig struct {
	Level string `json:"level"`
}

type sarifRuleProperties struct {
	Tags     []string `json:"tags"`
	Security string   `json:"security-severity"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID              string                `json:"ruleId"`
	RuleIndex           int                   `json:"ruleIndex"`
	Level               string                `json:"level"`
	Message             sarifMessage          `json:"message"`
	Locations           []sarifLocation       `json:"locations,omitempty"`
	PartialFingerprints map[string]string     `json:"partialFingerprints,omitempty"`
	Properties          sarifResultProperties `json:"properties,omitempty"`
}

type sarifResultProperties struct {
	FindingClass string `json:"findingClass"`
	Confidence   string `json:"confidence"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}
