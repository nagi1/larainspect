# Contributing

This repository is intended to stay beginner-friendly, explicit, and easy to extend.

## Go version

- Minimum supported Go version: `1.23`
- The foundation phase targets Go `1.23` to keep contributor setup simple and aligned with the current project toolchain.

## Dependency policy

- The foundation is intentionally standard-library-only.
- A third-party package should only be added when it clearly reduces maintenance cost or improves safety, parsing quality, CLI usability, or test quality.
- Every non-trivial dependency should be documented in the relevant phase when it is introduced.

## Commands

- Run tests: `go test ./...`
- Run the CLI: `go run ./cmd/larainspect audit`
- Render JSON: `go run ./cmd/larainspect audit --format json`

## Exit-code contract

- `0`: clean audit with no findings or unknowns
- `2`: usage or flag error
- `10`: low or informational risk, or unknown-only result
- `20`: medium-risk finding present
- `30`: high-risk finding present
- `40`: critical-risk finding present
- `50`: audit execution failure

## Testing strategy

- Keep unit tests close to the package under test.
- Put deterministic fixture builders in `internal/testfixtures`.
- Keep golden outputs in package `testdata/` directories.
- Update golden files deliberately when a public output contract changes.
- Avoid network access and mutable host assumptions in tests.

## Package boundaries

- `cmd/larainspect`: binary entrypoint only
- `internal/cli`: argument parsing and command orchestration
- `internal/model`: stable audit contracts and shared data model
- `internal/runner`: audited command execution
- `internal/discovery`: snapshot discovery contracts and placeholder service
- `internal/checks`: check registration and execution contracts
- `internal/correlators`: cross-signal correlation contracts
- `internal/report`: reporter interfaces
- `internal/report/terminal`: terminal renderer
- `internal/report/json`: JSON renderer
- `internal/report/schema`: public JSON schema draft
- `internal/testfixtures`: deterministic fixtures for tests

## Adding a new check

1. Add a new file in `internal/checks`.
2. Implement the `Check` interface.
3. Register it with `MustRegister` in an `init` function.
4. Add table-driven tests for the check.
5. Add or update fixture data if the public report output changes.

Checks must not execute shell commands directly. Use the execution context's command executor.
Package-level guidance for the extension points lives in the local `doc.go` files under `internal/checks`, `internal/discovery`, `internal/correlators`, and `internal/report/schema`.

## Golden-file rules

- Golden files are public-contract tests, not snapshots of incidental formatting.
- Prefer readable examples that help contributors understand the intended report shape.
- If a change is intentional, update the golden file in the same patch as the code change.

## Concurrency model

- Foundation keeps execution sequential for determinism.
- The shared execution context already carries a `WorkerLimit` so later phases can add bounded concurrency without changing public contracts.
- Future parallel work must stay context-aware, deterministic in output ordering, and safe for production hosts.
