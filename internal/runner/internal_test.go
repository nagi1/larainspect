package runner

import (
	"context"
	"errors"
	"runtime"
	"testing"
	"time"

	"github.com/nagi1/larainspect/internal/model"
	"github.com/nagi1/larainspect/internal/progress"
)

func TestSpecificationValidateBranches(t *testing.T) {
	t.Parallel()

	spec := Specification{
		Name:            "demo",
		AllowedFlags:    map[string]struct{}{"-n": {}},
		AllowedPrefixes: []string{"--format="},
		AllowPaths:      true,
		AllowValues:     true,
		MaxArgs:         4,
	}

	validArgs := [][]string{
		{"-n"},
		{"--format=json"},
		{"/tmp/demo"},
		{"value"},
	}
	for _, args := range validArgs {
		if err := spec.Validate(args); err != nil {
			t.Fatalf("Validate(%v) error = %v", args, err)
		}
	}

	if err := spec.Validate([]string{"a", "b", "c", "d", "e"}); err == nil {
		t.Fatal("expected max args error")
	}
	if err := spec.Validate([]string{"--bad"}); err == nil {
		t.Fatal("expected allowlist error")
	}
}

func TestNewCommandRunnerDefaults(t *testing.T) {
	t.Parallel()

	commandRunner := NewCommandRunner(0, 0, nil)
	if commandRunner.timeout <= 0 || commandRunner.maxOutputBytes <= 0 || commandRunner.allowlist == nil {
		t.Fatalf("expected defaults to be applied: %+v", commandRunner)
	}
}

func TestAllowlistValidateUnknownCommand(t *testing.T) {
	t.Parallel()

	err := DefaultAllowlist().Validate(model.CommandRequest{Name: "unknown"})
	if !errors.Is(err, ErrCommandRejected) {
		t.Fatalf("expected ErrCommandRejected, got %v", err)
	}
}

func TestAllowlistValidateAllowsFullPathForKnownCommand(t *testing.T) {
	t.Parallel()

	err := DefaultAllowlist().Validate(model.CommandRequest{Name: "/www/server/nginx/sbin/nginx", Args: []string{"-T"}})
	if err != nil {
		t.Fatalf("expected full-path nginx command to be allowed, got %v", err)
	}
}

func TestCommandRunnerHandlesNonZeroExitAndTruncation(t *testing.T) {
	t.Parallel()

	commandRunner := NewCommandRunner(time.Second, 4, NewAllowlist([]Specification{
		{Name: "ls", AllowPaths: true},
	}))

	result, err := commandRunner.Run(context.Background(), model.CommandRequest{Name: "ls", Args: []string{"/definitely/missing"}})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.ExitCode == 0 {
		t.Fatalf("expected non-zero exit code, got %d", result.ExitCode)
	}
	if !result.Truncated {
		t.Fatalf("expected truncation for bounded stderr/stdout, got %+v", result)
	}
}

func TestCaptureBufferBranches(t *testing.T) {
	t.Parallel()

	zero := newCaptureBuffer(0)
	if _, err := zero.Write([]byte("demo")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if !zero.Truncated() {
		t.Fatal("expected zero-limit buffer to truncate")
	}

	buffer := newCaptureBuffer(3)
	if _, err := buffer.Write([]byte("abcd")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if buffer.String() != "abc" {
		t.Fatalf("expected truncated buffer, got %q", buffer.String())
	}

	if _, err := buffer.Write([]byte("z")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if !buffer.Truncated() {
		t.Fatal("expected full buffer to stay truncated")
	}
}

func TestIsPathArgument(t *testing.T) {
	t.Parallel()

	if !isPathArgument("/tmp/demo") || !isPathArgument("./demo") || !isPathArgument("../demo") {
		t.Fatal("expected path arguments to be detected")
	}
	if isPathArgument("demo") {
		t.Fatal("expected plain value not to be treated as path")
	}
}

func TestDefaultWorkerLimit(t *testing.T) {
	t.Parallel()

	limit := DefaultWorkerLimit()
	if limit < 1 {
		t.Fatalf("expected limit >= 1, got %d", limit)
	}
	if limit > 4 {
		t.Fatalf("expected limit <= 4, got %d", limit)
	}
	if limit > runtime.NumCPU() {
		t.Fatalf("expected limit <= NumCPU (%d), got %d", runtime.NumCPU(), limit)
	}
}

func TestDiscoverySummaryFormat(t *testing.T) {
	t.Parallel()

	snapshot := model.Snapshot{
		Apps:       []model.LaravelApp{{}, {}},
		NginxSites: []model.NginxSite{{}},
	}
	summary := discoverySummary(snapshot, 3)

	if summary != "apps=2 nginx_sites=1 php_fpm_pools=0 listeners=0 unknowns=3" {
		t.Fatalf("unexpected summary: %q", summary)
	}
}

func TestDiscoverySummaryEmpty(t *testing.T) {
	t.Parallel()

	summary := discoverySummary(model.Snapshot{}, 0)
	if summary != "apps=0 nginx_sites=0 php_fpm_pools=0 listeners=0 unknowns=0" {
		t.Fatalf("unexpected empty summary: %q", summary)
	}
}

func TestFindingsSummaryCountsByClass(t *testing.T) {
	t.Parallel()

	findings := []model.Finding{
		{Class: model.FindingClassDirect},
		{Class: model.FindingClassDirect},
		{Class: model.FindingClassHeuristic},
		{Class: model.FindingClassCompromiseIndicator},
	}
	unknowns := []model.Unknown{{}, {}}

	summary := findingsSummary(findings, unknowns)
	if summary != "direct=2 heuristic=1 compromise=1 unknowns=2" {
		t.Fatalf("unexpected findings summary: %q", summary)
	}
}

func TestExecutionUnknownFields(t *testing.T) {
	t.Parallel()

	unknown := executionUnknown("check_id", "Something broke", errors.New("test error"))

	if unknown.ID != "check_id.error" {
		t.Fatalf("expected ID %q, got %q", "check_id.error", unknown.ID)
	}
	if unknown.CheckID != "check_id" {
		t.Fatalf("expected CheckID %q, got %q", "check_id", unknown.CheckID)
	}
	if unknown.Reason != "test error" {
		t.Fatalf("expected Reason %q, got %q", "test error", unknown.Reason)
	}
	if unknown.Error != model.ErrorKindCommandFailed {
		t.Fatalf("expected ErrorKind %q, got %q", model.ErrorKindCommandFailed, unknown.Error)
	}
}

func TestDiscoveryContextEventWithApps(t *testing.T) {
	t.Parallel()

	snapshot := model.Snapshot{
		Apps: []model.LaravelApp{
			{
				RootPath:   "/var/www/shop",
				PHPVersion: "8.2",
				Packages:   []model.PackageRecord{{Name: "laravel/framework"}},
			},
		},
		NginxSites:  []model.NginxSite{{}},
		PHPFPMPools: []model.PHPFPMPool{{}, {}},
		Listeners:   []model.ListenerRecord{{}},
	}

	event := discoveryContextEvent(snapshot)
	if event.Type != progress.EventContextResolved {
		t.Fatalf("expected EventContextResolved, got %v", event.Type)
	}
	if event.AppCount != 1 || event.NginxSites != 1 || event.PHPFPMPools != 2 || event.Listeners != 1 {
		t.Fatalf("unexpected event counts: %+v", event)
	}
	if event.AppPath != "/var/www/shop" || event.PHPVersion != "8.2" {
		t.Fatalf("unexpected app details: path=%q php=%q", event.AppPath, event.PHPVersion)
	}
	if event.PackageCount != 1 {
		t.Fatalf("expected 1 package, got %d", event.PackageCount)
	}
}

func TestDiscoveryContextEventEmpty(t *testing.T) {
	t.Parallel()

	event := discoveryContextEvent(model.Snapshot{})
	if event.AppCount != 0 || event.AppPath != "" {
		t.Fatalf("expected empty event for no apps: %+v", event)
	}
}

func TestRuntimeHostname(t *testing.T) {
	t.Parallel()

	hostname, err := runtimeHostname()
	if err != nil {
		t.Fatalf("runtimeHostname() error = %v", err)
	}
	if hostname == "" {
		t.Fatal("expected non-empty hostname")
	}
}

func TestSpecificationAllowsArgument(t *testing.T) {
	t.Parallel()

	spec := Specification{
		Name:            "test",
		AllowedFlags:    map[string]struct{}{"-v": {}},
		AllowedPrefixes: []string{"--format="},
		AllowPaths:      true,
		AllowValues:     true,
		MaxArgs:         10,
	}

	if !spec.allowsArgument("-v") {
		t.Fatal("expected flag to be allowed")
	}
	if !spec.allowsArgument("--format=json") {
		t.Fatal("expected prefix to be allowed")
	}
	if !spec.allowsArgument("/tmp/file") {
		t.Fatal("expected path to be allowed")
	}

	noPathsSpec := Specification{
		Name:    "test",
		MaxArgs: 10,
	}
	if noPathsSpec.allowsArgument("/tmp/file") {
		t.Fatal("expected path to be rejected when AllowPaths=false")
	}
	if noPathsSpec.allowsArgument("value") {
		t.Fatal("expected value to be rejected when AllowValues=false")
	}
}

func TestHasAllowedPrefix(t *testing.T) {
	t.Parallel()

	spec := Specification{
		AllowedPrefixes: []string{"--format=", "--scope="},
	}

	if !spec.hasAllowedPrefix("--format=json") {
		t.Fatal("expected prefix match")
	}
	if spec.hasAllowedPrefix("--bad-prefix") {
		t.Fatal("expected no prefix match")
	}
}
