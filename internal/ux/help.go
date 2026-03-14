package ux

import bannerart "github.com/nagi1/larainspect/art"

func Banner() string {
	return bannerart.Banner()
}

func RootHelp() string {
	return Banner() + `

larainspect

Read-only Laravel VPS auditor for operators under pressure.

Safety promises:
  - never mutates files, permissions, services, or firewall rules
  - keeps direct findings, heuristics, compromise indicators, and unknowns separate
  - stays usable in automation and optional guided mode

Usage:
  larainspect audit [flags]
  larainspect controls [flags]
  larainspect help
  larainspect version

Quick start:
  larainspect audit
  larainspect audit --scope app --app-path /var/www/shop
  larainspect audit --config /etc/larainspect/config.yaml
  larainspect audit --interactive
  larainspect audit --format json --verbosity quiet
  larainspect audit --report-markdown-path /tmp/larainspect-report.md

Commands:
  audit     Run the read-only audit workflow
  controls  List normalized external security controls and check mappings
  help      Show command help
  version   Print the development version

Learn more:
  Use 'larainspect audit --help' for flags, onboarding, interactive guidance, and exit codes.
  Use 'larainspect controls --help' to inspect the normalized external control map.
`
}

func AuditHelp() string {
	return `larainspect audit

Run the read-only audit workflow.

This command is designed to stay safe on production systems. It never writes to
application code, service config, permissions, or runtime state.

Usage:
  larainspect audit [flags]

Examples:
  larainspect audit
  larainspect audit --scope app --app-path /var/www/shop
  larainspect audit --scan-root /var/www --scan-root /srv/www
  larainspect audit --config /etc/larainspect/config.yaml
  larainspect audit --interactive
  larainspect audit --format json --verbosity quiet
  larainspect audit --report-json-path /tmp/larainspect-report.json
  larainspect audit --report-markdown-path /tmp/larainspect-report.md
  larainspect audit --debug-log-path /tmp/larainspect-debug.log
  larainspect audit --verbosity verbose --screen-reader

Helpful modes:
  quiet        Minimal terminal chatter for scripts and focused reruns
  normal       Plain-language onboarding with the standard report
  verbose      Adds operator-facing config summary and next-step guidance
  interactive  Prompts for missing app-focused input without breaking automation defaults

Accessibility:
  - foundation output uses plain ASCII text and no ANSI colors
  - --screen-reader keeps guidance compact and explicit
  - --verbosity quiet removes extra onboarding/footer copy
  - JSON output remains clean on stdout for machine consumers

Flags:
  --config string            Path to an audit config file (YAML or JSON)
  --format string            Output format: terminal, json, or markdown (default "terminal")
  --verbosity string         Output detail: quiet, normal, or verbose (default "normal")
  --scope string             Scan scope: auto, host, or app (default "auto")
  --app-path string          App path to prioritize when scope=app
  --scan-root value          Additional root to scan for Laravel apps; may be repeated
  --interactive              Enable guided prompts for missing app-focused input
  --report-json-path string  Optional path to also write the JSON report artifact
  --report-markdown-path string Optional path to also write the Markdown report artifact
  --debug-log-path string    Optional path to write a developer debug log with progress events and command executions
  --color string             Color preference for later styled output: auto, always, or never (default "auto")
  --no-color                 Shortcut for --color never
  --screen-reader            Prefer concise, explicit guidance for screen-reader use
  --command-timeout duration Timeout for one allowlisted command (default 2s)
  --max-output-bytes int     Maximum bytes captured per command stream (default 65536)
  --worker-limit int         Reserved worker cap for bounded concurrency

Config files:
  larainspect auto-loads from the first file found:
    larainspect.yaml, larainspect.yml, .larainspect.yaml, .larainspect.yml,
    larainspect.json, .larainspect.json, /etc/larainspect/config.yaml,
    or /etc/larainspect/config.json.
  Use --config to pick a specific file. YAML and JSON are both supported.

Exit codes:
  0   clean audit with no findings or unknowns
  2   usage or flag error
  10  low or informational risk, or unknown-only audit result
  20  medium-risk finding present
  30  high-risk finding present
  40  critical-risk finding present
  50  audit execution failure
`
}

func ControlsHelp() string {
	return `larainspect controls

List the normalized external security controls that drive Larainspect's
implementation boundary and map them to real check IDs.

Usage:
  larainspect controls [flags]

Examples:
  larainspect controls
  larainspect controls --status implemented
  larainspect controls --status partial --check-id source.security
  larainspect controls --format json

Flags:
  --format string      Output format: text or json (default "text")
  --status strings     Filter by status: implemented, partial, queued, or out_of_scope
  --check-id strings   Filter to controls mapped to the given check ID; may be repeated
`
}
