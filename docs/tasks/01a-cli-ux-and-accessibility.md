# 01A CLI UX And Accessibility

## Status

CLI UX and accessibility are implemented.

## Goal

Design and implement a CLI experience that is highly helpful, informative, configurable, interactive where useful, accessible, and easy for beginners to use without reducing value for experienced operators.

## Tasks

- Define the UX principles for the CLI: clarity, safety, accessibility, progressive disclosure, and operator trust.
- Design the command help, examples, onboarding text, and flag descriptions so new users can understand what the tool does quickly.
- Define a configuration model for output format, verbosity, scan scope, interactivity, and operator preferences.
- Design interactive flows that improve usability safely, such as guided app-path selection or confirmation of ambiguous targets, while remaining optional for automation.
- Define accessibility expectations for color usage, text structure, quiet mode, verbose mode, and screen-reader-friendly output.
- Define beginner-friendly report affordances such as plain-language explanations, remediation summaries, and recommended next steps.
- Define expert-friendly affordances such as focused evidence output, machine-readable modes, and controllable verbosity.
- Keep UX code and presentation helpers separate from detection logic and check execution.
- Add CLI-focused tests for help output, flag behavior, onboarding text, and interactive/non-interactive flows.
- Document UX and CLI behavior conventions so OSS contributors extend the interface consistently.

## Deliverables

- documented CLI UX principles
- initial command help and usage content standards
- configuration and interactivity design for the CLI surface
- accessibility and output-style rules
- regression tests covering CLI help, flags, and representative UX flows

## Implemented Artifacts

- CLI command and flag wiring:
  - [app.go](/Users/nagi/code/larainspect/internal/cli/app.go)
  - [audit.go](/Users/nagi/code/larainspect/internal/cli/audit.go)
- UX helpers and guided prompts:
  - [help.go](/Users/nagi/code/larainspect/internal/ux/help.go)
  - [messages.go](/Users/nagi/code/larainspect/internal/ux/messages.go)
  - [prompt.go](/Users/nagi/code/larainspect/internal/ux/prompt.go)
- UX and accessibility documentation:
  - [cli-ux-and-accessibility.md](/Users/nagi/code/larainspect/docs/cli-ux-and-accessibility.md)
  - [CONTRIBUTING.md](/Users/nagi/code/larainspect/CONTRIBUTING.md)
- Regression tests:
  - [app_test.go](/Users/nagi/code/larainspect/internal/cli/app_test.go)

## Verification

Representative UX verification currently includes:

- `go test ./internal/cli ./internal/ux ./internal/model`
- `go run ./cmd/larainspect audit`
- `go run ./cmd/larainspect audit --interactive`
- `go run ./cmd/larainspect audit --format json --verbosity quiet`

Covered behaviors:

- root help content
- audit help content
- app-scope validation in non-interactive mode
- guided app-path prompting in interactive mode
- verbose onboarding and next-step guidance
- quiet-mode suppression of extra UX copy
- JSON-mode clean stdout behavior

## Blockers To Watch

- interactive features that break automation or scripted usage
- beginner-friendly output becoming vague or technically inaccurate
- accessibility concerns being deferred until after the command surface hardens
- UX logic becoming tangled with checks, discovery, or reporters

## Acceptance Notes

- The CLI must remain fully usable in non-interactive automation contexts.
- Interactivity should improve comprehension and safety, not add friction.
- Helpful output should use plain language where appropriate, but still preserve exact evidence and severity semantics.
- UX work is not complete until representative CLI flows are tested.
