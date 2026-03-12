// Package schema defines the machine-readable JSON report document shape.
//
// The foundation phase keeps the schema draft aligned with model.Report and
// versioned by model.SchemaVersion. Later phases can extend the document while
// preserving backward-compatible behavior for existing fields.
package schema
