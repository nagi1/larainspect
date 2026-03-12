# larainspect Docs

This directory is the design, planning, and decision record for `larainspect`.

`larainspect` is intended to become an open-source, read-only Go CLI that audits Laravel VPS deployments with a Laravel-style operator experience while staying safe to run on production systems.

Start here:

- [Project Prompt](/Users/nagi/code/larainspect/docs/project-prompt.md)
- [Project Constitution](/Users/nagi/code/larainspect/docs/project-constitution.md)
- [Architecture](/Users/nagi/code/larainspect/docs/architecture.md)
- [Security Checklist](/Users/nagi/code/larainspect/docs/security-checklist.md)
- [Long-Term Memory](/Users/nagi/code/larainspect/docs/long-term-memory.md)
- [Foundation Contracts](/Users/nagi/code/larainspect/docs/foundation-contracts.md)
- [Task Breakdown](/Users/nagi/code/larainspect/docs/tasks/README.md)

Working rules:

- Keep implementation aligned with the security-first, read-only audit contract.
- Treat heuristics, confirmed findings, compromise indicators, and unknowns as separate output classes.
- Prefer evidence from filesystem state, process state, service config, listeners, Laravel metadata, and bounded logs.
- Keep the Go codebase modular so contributors can add new checks without rewriting core execution or reporters.
- Apply `DRY` and `KISS` during implementation; prefer small, obvious building blocks over duplicated logic or clever abstractions.
- Use descriptive names and clear package boundaries so OSS contributors can navigate the codebase quickly.
- Prefer the standard library and mature Go ecosystem packages over writing everything from scratch.
- Update the long-term memory when a decision becomes stable enough to affect architecture, testing, or contributor workflow.
- Complete the design artifacts first; do not start implementation until the design and check inventory are accepted.
