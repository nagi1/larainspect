// Package checks defines the stable contract for direct audit checks.
//
// Checks are registered at compile time and must remain read-only.
// A check receives the shared execution context and normalized snapshot,
// then returns findings and unknowns without performing its own shell execution.
//
// New checks should:
//   - implement the Check interface
//   - use a stable, descriptive ID
//   - call MustRegister from an init function
//   - delegate any command execution to execution.Commands
package checks
