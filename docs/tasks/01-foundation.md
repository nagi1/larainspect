# 01 Foundation

## Status

Foundation is implemented.

## Goal

Create the maintainable project skeleton and the stable public contracts after the architecture and audit inventory are accepted.

## Tasks

- Initialize the standalone Go CLI project structure for `larainspect`.
- Define the CLI entrypoint and command surface for `audit`.
- Select and document the latest broadly compatible Go version target for OSS contributors.
- Implement the finding model, severity taxonomy, confidence taxonomy, and unknown/error model.
- Implement reporter interfaces for terminal and JSON output.
- Implement the safe command-runner abstraction with timeout, capture, exit status, and command allowlisting.
- Define the shared execution context passed into discovery and checks.
- Define check registration/loading so new checks do not require core rewrites.
- Create the first test fixtures and golden-output harness.
- Lock the package boundaries for `runner`, `discovery`, `checks`, `correlators`, and `reporters`.
- Make the codebase easy for open-source contributors to extend with new checks and parsers.
- Keep the CLI experience Laravel-like in readability without coupling it to Laravel internals.
- Choose ecosystem packages pragmatically instead of building every helper from scratch, and document why each dependency exists.
- Establish naming and package-organization conventions that favor descriptive identifiers and maintainability.
- Define the repository testing strategy using Go conventions, including fixture layout, golden test rules, and command(s) contributors should run.
- Define the initial concurrency model, worker-limit strategy, and context propagation rules so later phases can stay fast without becoming hard to reason about.

## Deliverables

- runnable Go CLI skeleton
- stable finding schema
- stable JSON schema draft
- contributor-safe extension pattern
- command runner with explicit allowed commands and no shell interpolation

## Implemented Artifacts

- CLI entrypoint and command surface:
  - [main.go](/Users/nagi/code/larainspect/cmd/larainspect/main.go)
  - [app.go](/Users/nagi/code/larainspect/internal/cli/app.go)
  - [audit.go](/Users/nagi/code/larainspect/internal/cli/audit.go)
- Stable audit model and exit-code contracts:
  - [finding.go](/Users/nagi/code/larainspect/internal/model/finding.go)
  - [exitcode.go](/Users/nagi/code/larainspect/internal/model/exitcode.go)
- Reporter contracts and implementations:
  - [reporter.go](/Users/nagi/code/larainspect/internal/report/reporter.go)
  - [reporter.go](/Users/nagi/code/larainspect/internal/report/terminal/reporter.go)
  - [reporter.go](/Users/nagi/code/larainspect/internal/report/json/reporter.go)
  - [report.schema.json](/Users/nagi/code/larainspect/internal/report/schema/report.schema.json)
- Safe command runner and audit orchestration:
  - [command.go](/Users/nagi/code/larainspect/internal/runner/command.go)
  - [audit.go](/Users/nagi/code/larainspect/internal/runner/audit.go)
- Extension points for later phases:
  - [check.go](/Users/nagi/code/larainspect/internal/checks/check.go)
  - [service.go](/Users/nagi/code/larainspect/internal/discovery/service.go)
  - [correlator.go](/Users/nagi/code/larainspect/internal/correlators/correlator.go)
- Contributor and contract documentation:
  - [README.md](/Users/nagi/code/larainspect/README.md)
  - [CONTRIBUTING.md](/Users/nagi/code/larainspect/CONTRIBUTING.md)
  - [foundation-contracts.md](/Users/nagi/code/larainspect/docs/foundation-contracts.md)

## Verification

Foundation verification currently uses:

- `go test ./...`
- `go run ./cmd/larainspect audit`
- `go run ./cmd/larainspect audit --format json`

The base harness currently covers:

- model validation and report grouping
- exit-code mapping
- command-runner allowlisting, capture, and timeout behavior
- registry ordering and duplicate protection
- audit orchestration behavior
- terminal and JSON golden output
- embedded JSON schema draft validity

## Boundary For Later Tasks

Foundation intentionally stops before real host inspection logic.

Not implemented here:

- Laravel discovery
- subsystem parsers
- direct Laravel or VPS security checks
- real correlators
- interactive UX flows from `01A`
- any mutation or remediation behavior

## Blockers To Watch

- Over-coupling reporters to detection logic
- Letting checks run ad hoc shell commands outside the runner
- Mixing heuristics with confirmed findings in one code path
- Starting implementation before architecture, check inventory, and sample finding formats are stable

## Acceptance Notes

- Do not implement a `--fix` mode.
- Do not add internet-dependent package or advisory checks to the runtime path.
- Preserve room for future subsystem-specific fixtures and parser tests.
- Prefer standard library or established Go packages over custom infrastructure where the ecosystem already solves the problem well.
- Keep abstractions simple enough that a new OSS contributor can understand the package flow quickly.
- Foundation is not complete until the base test harness runs cleanly and is documented.
- Foundation should leave room for controlled parallelism without forcing concurrency into every code path.
