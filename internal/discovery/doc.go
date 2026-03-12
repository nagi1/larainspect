// Package discovery defines the normalized snapshot collection contract.
//
// Discovery is responsible for collecting raw host evidence once and returning
// a shared snapshot that later checks and correlators can reuse.
// It should not render output or make severity decisions.
package discovery
