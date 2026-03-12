# CLI UX And Accessibility

This document captures the stable UX rules introduced in `01A`.

It is intentionally practical. The goal is to keep future CLI work coherent and contributor-friendly as discovery and check coverage expand.

## UX Principles

- clarity over cleverness
- safety before convenience
- progressive disclosure instead of noisy default output
- automation-safe defaults
- explicit evidence terminology
- accessibility through plain text, stable structure, and optional guidance
- beginner-friendly explanations without hiding expert detail

## Current UX Surface

The audit command currently supports:

- output formats:
  - `terminal`
  - `json`
- verbosity levels:
  - `quiet`
  - `normal`
  - `verbose`
- scan scopes:
  - `auto`
  - `host`
  - `app`
- optional guided mode:
  - `--interactive`
- accessibility preferences:
  - `--screen-reader`
  - `--color`
  - `--no-color`
- focused app targeting:
  - `--app-path`

## Help And Onboarding Rules

Root help should explain:

- what the tool is
- the read-only safety promise
- the common audit entrypoints
- where to get deeper audit help

Audit help should explain:

- what the command does
- why it is safe on production systems
- the difference between quiet, normal, verbose, and interactive modes
- accessibility behavior
- examples for both beginner and expert usage
- stable exit codes

Terminal onboarding should:

- appear in `normal` and `verbose` terminal runs
- stay off in `quiet`
- never appear in JSON mode on stdout
- stay plain-language and short

Verbose mode should add:

- operator-facing config summary
- clearer next-step guidance

Quiet mode should:

- avoid extra onboarding and footer copy
- leave the main report readable and script-friendly

## Interactive Mode Rules

Interactive mode is opt-in only.

Rules:

- never prompt unless `--interactive` is set
- keep JSON output clean on stdout
- send prompts and guided messages to stderr
- prompt only when it reduces ambiguity or fills in missing operator intent
- if `scope=app` and no `--app-path` is provided:
  - guided mode should prompt for it
  - non-interactive mode should fail with a clear error and recovery hint

The current guided flow supports:

- choosing a scope when the default is still `auto`
- entering an app path for app-focused audits

## Accessibility Rules

Foundation accessibility behavior is intentionally conservative:

- plain ASCII text
- no ANSI colors in the foundation output
- stable section ordering
- explicit labels such as `Why`, `Evidence`, `Remediation`, and `Reason`
- optional `--screen-reader` mode for concise guidance
- JSON output unaffected by onboarding or prompt text on stdout

## Contributor Rules

When extending the CLI:

- keep UX helpers in `internal/ux`
- keep detection and execution logic out of UX helpers
- preserve clean stdout for machine-readable modes
- add CLI-focused regression tests for new flags or interactive flows
- prefer additive guidance over surprising implicit behavior

## Reference Files

- root command wiring: [app.go](/Users/nagi/code/larainspect/internal/cli/app.go)
- audit command wiring: [audit.go](/Users/nagi/code/larainspect/internal/cli/audit.go)
- UX helpers: [help.go](/Users/nagi/code/larainspect/internal/ux/help.go)
- onboarding/footer text: [messages.go](/Users/nagi/code/larainspect/internal/ux/messages.go)
- interactive prompts: [prompt.go](/Users/nagi/code/larainspect/internal/ux/prompt.go)
