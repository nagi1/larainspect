package model

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"time"
)

const SchemaVersion = "v0alpha1"

type Severity string

const (
	SeverityCritical      Severity = "critical"
	SeverityHigh          Severity = "high"
	SeverityMedium        Severity = "medium"
	SeverityLow           Severity = "low"
	SeverityInformational Severity = "informational"
)

func (severity Severity) Valid() bool {
	switch severity {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInformational:
		return true
	default:
		return false
	}
}

// Weight returns a numeric weight for sorting where higher means more severe.
// Unknown severities return 0.
func (severity Severity) Weight() int {
	switch severity {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInformational:
		return 1
	default:
		return 0
	}
}

type Confidence string

const (
	ConfidenceConfirmed         Confidence = "confirmed"
	ConfidenceProbable          Confidence = "probable"
	ConfidencePossible          Confidence = "possible"
	ConfidenceNotEnoughEvidence Confidence = "not_enough_evidence"
)

func (confidence Confidence) Valid() bool {
	switch confidence {
	case ConfidenceConfirmed, ConfidenceProbable, ConfidencePossible, ConfidenceNotEnoughEvidence:
		return true
	default:
		return false
	}
}

type FindingClass string

const (
	FindingClassDirect              FindingClass = "direct_finding"
	FindingClassHeuristic           FindingClass = "heuristic_finding"
	FindingClassCompromiseIndicator FindingClass = "possible_compromise_indicator"
)

func (class FindingClass) Valid() bool {
	switch class {
	case FindingClassDirect, FindingClassHeuristic, FindingClassCompromiseIndicator:
		return true
	default:
		return false
	}
}

type ErrorKind string

const (
	ErrorKindPermissionDenied ErrorKind = "permission_denied"
	ErrorKindCommandRejected  ErrorKind = "command_rejected"
	ErrorKindCommandFailed    ErrorKind = "command_failed"
	ErrorKindCommandTimeout   ErrorKind = "command_timeout"
	ErrorKindCommandMissing   ErrorKind = "command_missing"
	ErrorKindParseFailure     ErrorKind = "parse_failure"
	ErrorKindNotEnoughData    ErrorKind = "not_enough_data"
)

func (kind ErrorKind) Valid() bool {
	switch kind {
	case ErrorKindPermissionDenied, ErrorKindCommandRejected, ErrorKindCommandFailed, ErrorKindCommandTimeout, ErrorKindCommandMissing, ErrorKindParseFailure, ErrorKindNotEnoughData:
		return true
	default:
		return false
	}
}

type Evidence struct {
	Label  string `json:"label"`
	Detail string `json:"detail"`
}

type Target struct {
	Type  string `json:"type"`
	Name  string `json:"name,omitempty"`
	Path  string `json:"path,omitempty"`
	Value string `json:"value,omitempty"`
}

type Finding struct {
	ID          string       `json:"id"`
	CheckID     string       `json:"check_id"`
	Class       FindingClass `json:"class"`
	Severity    Severity     `json:"severity"`
	Confidence  Confidence   `json:"confidence"`
	Title       string       `json:"title"`
	Why         string       `json:"why"`
	Remediation string       `json:"remediation"`
	Evidence    []Evidence   `json:"evidence"`
	Affected    []Target     `json:"affected,omitempty"`
}

func (finding Finding) Validate() error {
	switch {
	case strings.TrimSpace(finding.ID) == "":
		return errors.New("finding id is required")
	case strings.TrimSpace(finding.CheckID) == "":
		return errors.New("finding check id is required")
	case strings.TrimSpace(finding.Title) == "":
		return errors.New("finding title is required")
	case strings.TrimSpace(finding.Why) == "":
		return errors.New("finding why is required")
	case strings.TrimSpace(finding.Remediation) == "":
		return errors.New("finding remediation is required")
	case !finding.Class.Valid():
		return fmt.Errorf("finding class %q is invalid", finding.Class)
	case !finding.Severity.Valid():
		return fmt.Errorf("finding severity %q is invalid", finding.Severity)
	case !finding.Confidence.Valid():
		return fmt.Errorf("finding confidence %q is invalid", finding.Confidence)
	case len(finding.Evidence) == 0:
		return errors.New("finding evidence is required")
	default:
		return nil
	}
}

// Fingerprint returns a stable identity hash for baseline and dedup use.
// Based on check_id + class + finding id + first affected target.
// Wording changes to title/why/remediation do not alter the fingerprint.
func (finding Finding) Fingerprint() string {
	h := sha256.New()
	h.Write([]byte(finding.CheckID))
	h.Write([]byte{':'})
	h.Write([]byte(finding.Class))
	h.Write([]byte{':'})
	h.Write([]byte(finding.ID))
	if len(finding.Affected) > 0 {
		h.Write([]byte{':'})
		t := finding.Affected[0]
		if t.Path != "" {
			h.Write([]byte(t.Path))
		} else if t.Name != "" {
			h.Write([]byte(t.Name))
		} else if t.Value != "" {
			h.Write([]byte(t.Value))
		}
	}
	return fmt.Sprintf("%x", h.Sum(nil))[:16]
}

type Unknown struct {
	ID       string     `json:"id"`
	CheckID  string     `json:"check_id"`
	Title    string     `json:"title"`
	Reason   string     `json:"reason"`
	Error    ErrorKind  `json:"error_kind"`
	Evidence []Evidence `json:"evidence,omitempty"`
	Affected []Target   `json:"affected,omitempty"`
}

func (unknown Unknown) Validate() error {
	switch {
	case strings.TrimSpace(unknown.ID) == "":
		return errors.New("unknown id is required")
	case strings.TrimSpace(unknown.CheckID) == "":
		return errors.New("unknown check id is required")
	case strings.TrimSpace(unknown.Title) == "":
		return errors.New("unknown title is required")
	case strings.TrimSpace(unknown.Reason) == "":
		return errors.New("unknown reason is required")
	case strings.TrimSpace(string(unknown.Error)) == "":
		return errors.New("unknown error kind is required")
	case !unknown.Error.Valid():
		return fmt.Errorf("unknown error kind %q is invalid", unknown.Error)
	default:
		return nil
	}
}

type Summary struct {
	TotalFindings        int              `json:"total_findings"`
	DirectFindings       int              `json:"direct_findings"`
	HeuristicFindings    int              `json:"heuristic_findings"`
	CompromiseIndicators int              `json:"compromise_indicators"`
	Unknowns             int              `json:"unknowns"`
	SeverityCounts       map[Severity]int `json:"severity_counts"`
}

type Host struct {
	Hostname string `json:"hostname,omitempty"`
	OS       string `json:"os,omitempty"`
	Arch     string `json:"arch,omitempty"`
}

type ToolAvailability map[string]bool

type Snapshot struct {
	Host                  Host                      `json:"host"`
	Tools                 ToolAvailability          `json:"tools,omitempty"`
	Apps                  []LaravelApp              `json:"apps,omitempty"`
	NginxSites            []NginxSite               `json:"nginx_sites,omitempty"`
	PHPFPMPools           []PHPFPMPool              `json:"php_fpm_pools,omitempty"`
	PHPINIConfigs         []PHPINIConfig            `json:"php_ini_configs,omitempty"`
	MySQLConfigs          []MySQLConfig             `json:"mysql_configs,omitempty"`
	SupervisorPrograms    []SupervisorProgram       `json:"supervisor_programs,omitempty"`
	SupervisorHTTPServers []SupervisorHTTPServer    `json:"supervisor_http_servers,omitempty"`
	SystemdUnits          []SystemdUnit             `json:"systemd_units,omitempty"`
	CronEntries           []CronEntry               `json:"cron_entries,omitempty"`
	Listeners             []ListenerRecord          `json:"listeners,omitempty"`
	SSHConfigs            []SSHConfig               `json:"ssh_configs,omitempty"`
	SSHAccounts           []SSHAccount              `json:"ssh_accounts,omitempty"`
	SudoRules             []SudoRule                `json:"sudo_rules,omitempty"`
	FirewallSummaries     []FirewallSummary         `json:"firewall_summaries,omitempty"`
	RuleDefinitions       map[string]RuleDefinition `json:"-"`
}

type Report struct {
	SchemaVersion        string    `json:"schema_version"`
	GeneratedAt          time.Time `json:"generated_at"`
	Duration             string    `json:"duration"`
	Host                 Host      `json:"host"`
	Summary              Summary   `json:"summary"`
	DirectFindings       []Finding `json:"direct_findings"`
	HeuristicFindings    []Finding `json:"heuristic_findings"`
	CompromiseIndicators []Finding `json:"compromise_indicators"`
	Unknowns             []Unknown `json:"unknowns"`
}

func BuildReport(host Host, generatedAt time.Time, duration time.Duration, findings []Finding, unknowns []Unknown) (Report, error) {
	report := Report{
		SchemaVersion: SchemaVersion,
		GeneratedAt:   generatedAt.UTC(),
		Duration:      duration.Round(time.Millisecond).String(),
		Host:          host,
		Summary: Summary{SeverityCounts: map[Severity]int{
			SeverityCritical:      0,
			SeverityHigh:          0,
			SeverityMedium:        0,
			SeverityLow:           0,
			SeverityInformational: 0,
		}},
		DirectFindings:       []Finding{},
		HeuristicFindings:    []Finding{},
		CompromiseIndicators: []Finding{},
		Unknowns:             []Unknown{},
	}

	for _, finding := range findings {
		if err := finding.Validate(); err != nil {
			return Report{}, fmt.Errorf("validate finding %q: %w", finding.ID, err)
		}

		report.Summary.TotalFindings++
		report.Summary.SeverityCounts[finding.Severity]++

		switch finding.Class {
		case FindingClassDirect:
			report.DirectFindings = append(report.DirectFindings, finding)
			report.Summary.DirectFindings++
		case FindingClassHeuristic:
			report.HeuristicFindings = append(report.HeuristicFindings, finding)
			report.Summary.HeuristicFindings++
		case FindingClassCompromiseIndicator:
			report.CompromiseIndicators = append(report.CompromiseIndicators, finding)
			report.Summary.CompromiseIndicators++
		default:
			return Report{}, fmt.Errorf("unsupported finding class %q", finding.Class)
		}
	}

	for _, unknown := range unknowns {
		if err := unknown.Validate(); err != nil {
			return Report{}, fmt.Errorf("validate unknown %q: %w", unknown.ID, err)
		}

		report.Unknowns = append(report.Unknowns, unknown)
		report.Summary.Unknowns++
	}

	return report, nil
}

func (report Report) Findings() []Finding {
	findings := make([]Finding, 0, report.Summary.TotalFindings)
	findings = append(findings, report.DirectFindings...)
	findings = append(findings, report.HeuristicFindings...)
	findings = append(findings, report.CompromiseIndicators...)
	return findings
}

func RebuildReport(report Report, findings []Finding, unknowns []Unknown) (Report, error) {
	duration, err := time.ParseDuration(report.Duration)
	if err != nil {
		return Report{}, fmt.Errorf("parse report duration %q: %w", report.Duration, err)
	}

	rebuiltReport, err := BuildReport(report.Host, report.GeneratedAt, duration, findings, unknowns)
	if err != nil {
		return Report{}, err
	}

	return rebuiltReport, nil
}

type CheckResult struct {
	Findings []Finding
	Unknowns []Unknown
}

type AuditConfig struct {
	Format             string
	ReportJSONPath     string
	ReportMarkdownPath string
	ReportSARIFPath    string
	ReportHTMLPath     string
	DebugLogPath       string
	BaselinePath       string
	UpdateBaselinePath string
	StoreDir           string
	CommandTimeout     time.Duration
	MaxOutputBytes     int
	WorkerLimit        int
	ConfigPath         string
	Verbosity          Verbosity
	Scope              ScanScope
	Interactive        bool
	AppPath            string
	ScanRoots          []string
	ColorMode          ColorMode
	ScreenReader       bool
	Identities         IdentityConfig
	Profile            HostProfile
	Rules              RuleConfig
	VulnCheck          bool
}

type CommandRequest struct {
	Name string
	Args []string
}

type CommandResult struct {
	Command    CommandRequest `json:"command"`
	ExitCode   int            `json:"exit_code"`
	Stdout     string         `json:"stdout,omitempty"`
	Stderr     string         `json:"stderr,omitempty"`
	Duration   string         `json:"duration"`
	Truncated  bool           `json:"truncated"`
	TimedOut   bool           `json:"timed_out"`
	StartedAt  time.Time      `json:"started_at"`
	FinishedAt time.Time      `json:"finished_at"`
}

type CommandExecutor interface {
	Run(context.Context, CommandRequest) (CommandResult, error)
}

type ExecutionContext struct {
	AuditID   string
	StartedAt time.Time
	Config    AuditConfig
	Host      Host
	Tools     ToolAvailability
	Commands  CommandExecutor
}
