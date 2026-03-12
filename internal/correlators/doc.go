// Package correlators defines contracts for combining signals across checks.
//
// Correlators run after direct checks. They should use the normalized snapshot
// plus previously collected findings to emit higher-confidence or multi-signal
// results without reparsing raw host state.
package correlators
