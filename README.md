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

## Repository guide

- [Project docs](/Users/nagi/code/larainspect/docs/README.md)
- [Contributor guide](/Users/nagi/code/larainspect/CONTRIBUTING.md)
