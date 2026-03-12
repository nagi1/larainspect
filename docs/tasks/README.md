# Task Breakdown

This directory tracks implementation by subsystem instead of by file.

## Shared Implementation Standards

These rules apply to every implementation phase:

- follow `DRY`: extract shared parsing, evidence collection, correlation helpers, and report formatting logic instead of duplicating it across checks
- follow `KISS`: prefer simple, explicit designs over clever abstractions or deep framework-like indirection
- use descriptive method, function, type, package, and variable names; optimize for contributor readability over brevity
- target the latest broadly compatible Go release line practical for OSS adoption, and document the selected minimum Go version explicitly once chosen
- prefer mature, well-maintained Go ecosystem packages when they materially reduce risk, parsing complexity, or maintenance burden
- avoid reimplementing standard library or well-supported ecosystem capabilities from scratch unless there is a clear safety, portability, or auditability reason
- take advantage of Go's strengths when they are useful here: fast execution, simple distribution, strong tooling, and bounded concurrency
- use concurrency deliberately and only where it makes the auditor faster or more responsive without hurting safety, determinism, or maintainability
- keep dependencies small, reviewable, and justified; every non-trivial dependency should earn its place
- design for OSS contributors: clear package boundaries, low coupling, stable interfaces, and obvious extension points for new checks
- document non-obvious decisions close to the code and keep contributor-facing docs current as the implementation evolves
- keep tests and fixtures readable enough that contributors can add new checks without reverse-engineering hidden conventions
- implementation is not done until it is tested and shown to work through appropriate Go tests, fixtures, and representative end-to-end validation
- follow Go best practices and conventions for project layout, naming, error handling, table-driven tests, small interfaces, and standard tooling
- prefer deterministic tests that are safe to run in OSS CI and do not require a live VPS or internet access
- preserve production safety and the read-only audit contract over convenience

Phases:

- [01 Foundation](/Users/nagi/code/larainspect/docs/tasks/01-foundation.md)
- [01A CLI UX And Accessibility](/Users/nagi/code/larainspect/docs/tasks/01a-cli-ux-and-accessibility.md)
- [02 Discovery And Evidence](/Users/nagi/code/larainspect/docs/tasks/02-discovery-and-evidence.md)
- [03 Core Risk Checks](/Users/nagi/code/larainspect/docs/tasks/03-core-risk-checks.md)
- [04 Framework Heuristics](/Users/nagi/code/larainspect/docs/tasks/04-framework-heuristics.md)
- [04A Framework False-Positive Reduction](/Users/nagi/code/larainspect/docs/tasks/04a-framework-false-positive-reduction.md)
- [05 Operational Surface Checks](/Users/nagi/code/larainspect/docs/tasks/05-operational-surface-checks.md)
- [07 Dependency Vulnerability Intelligence](/Users/nagi/code/larainspect/docs/tasks/07-dependency-vulnerability-intelligence.md)
- [06 Correlation Reporting And Tests](/Users/nagi/code/larainspect/docs/tasks/06-correlation-reporting-and-tests.md)

Execution rule:

- finish and review the design docs before starting implementation tasks
- keep each phase independently reviewable for open-source contributors
- prefer adding a focused phase file instead of overloading an existing one
- apply the shared implementation standards in every phase, not only during foundation work

Management rules:

- Each task file should remain implementation-oriented, not aspirational.
- Mark blockers and assumptions explicitly.
- Keep cross-cutting changes in the latest relevant phase instead of duplicating them.
