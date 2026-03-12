# larainspect

`larainspect` is a read-only Go CLI for auditing Laravel VPS deployments.

The repository is currently in the foundation phase. The codebase now includes:

- a runnable `larainspect audit` command
- a stable finding and unknown-item model
- terminal and JSON reporters
- an audited command runner with allowlisting and bounded capture
- check, discovery, and correlator contracts for later phases
- fixture-driven reporter tests and golden outputs

## Goals

- safe to run on production systems
- open-source friendly package boundaries
- beginner-friendly output without hiding technical evidence
- fast execution with bounded, explicit concurrency rules

## Quick start

```bash
go test ./...
go run ./cmd/larainspect audit
go run ./cmd/larainspect audit --format json
```

## Exit codes

- `0`: clean audit with no findings or unknowns
- `2`: usage or flag error
- `10`: low or informational risk, or unknown-only result
- `20`: medium-risk finding present
- `30`: high-risk finding present
- `40`: critical-risk finding present
- `50`: audit execution failure

## Repository guide

- [Project docs](/Users/nagi/code/larainspect/docs/README.md)
- [Contributor guide](/Users/nagi/code/larainspect/CONTRIBUTING.md)
