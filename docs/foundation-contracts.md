# Foundation Contracts

This document describes the stable contracts that already exist after `task-1`.

It is intentionally narrower than the full architecture docs. The goal here is to make the current implementation surface easy for open-source contributors, test writers, and downstream integrators to understand.

## Current Scope

The foundation phase currently provides:

- a runnable `larainspect audit` command
- a read-only audit orchestration skeleton
- a finding, unknown, and summary data model
- terminal and JSON reporters
- a command runner with explicit allowlisting
- compile-time check registration
- a JSON schema draft for machine-readable output
- fixture-driven and golden-file tests

It does not yet provide:

- real Laravel app discovery
- real subsystem parsers
- real risk checks
- real correlation logic across host signals
- any remediation or mutation mode

## Stable Public Contracts

The following are considered stable enough for further implementation work:

- CLI subcommand: `larainspect audit`
- report schema version: `v0alpha1`
- finding severities:
  - `critical`
  - `high`
  - `medium`
  - `low`
  - `informational`
- confidence levels:
  - `confirmed`
  - `probable`
  - `possible`
  - `not_enough_evidence`
- finding classes:
  - `direct_finding`
  - `heuristic_finding`
  - `possible_compromise_indicator`
- unknown error kinds:
  - `permission_denied`
  - `command_rejected`
  - `command_failed`
  - `command_timeout`
  - `command_missing`
  - `parse_failure`
  - `not_enough_data`
- exit codes:
  - `0`
  - `2`
  - `10`
  - `20`
  - `30`
  - `40`
  - `50`

## JSON Schema Draft

The explicit JSON schema draft lives at:

- [report.schema.json](/Users/nagi/code/larainspect/internal/report/schema/report.schema.json)

The Go accessor for tooling lives at:

- [schema.go](/Users/nagi/code/larainspect/internal/report/schema/schema.go)

Current guarantees:

- the schema version is pinned to `v0alpha1`
- `severity_counts` always includes all severity buckets, even when they are zero
- top-level report sections are always present
- terminal and JSON reporters are rendered from the same normalized report model

## Extension Points

Current extension points:

- checks: [check.go](/Users/nagi/code/larainspect/internal/checks/check.go)
- discovery: [service.go](/Users/nagi/code/larainspect/internal/discovery/service.go)
- correlators: [correlator.go](/Users/nagi/code/larainspect/internal/correlators/correlator.go)
- reporters: [reporter.go](/Users/nagi/code/larainspect/internal/report/reporter.go)

Rules:

- checks must not execute shell commands directly
- reporters must not contain detection logic
- discovery owns raw evidence collection and snapshot normalization
- correlators combine existing signals; they should not duplicate subsystem parsing
- package-level `doc.go` files describe the intended responsibility of each extension area

## Testing Contracts

Current test contract:

- package unit tests live next to implementation
- golden files live under local `testdata/`
- deterministic shared fixtures live under `internal/testfixtures`
- command examples and schema-level behaviors should stay regression-tested before new phases build on them
