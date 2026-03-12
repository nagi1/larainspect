package checks

import (
	"context"

	"github.com/nagi1/larainspect/internal/model"
)

const operationalForensicsCheckID = "operations.forensics"

type OperationalForensicsCheck struct{}

func init() {
	MustRegister(OperationalForensicsCheck{})
}

func (OperationalForensicsCheck) ID() string {
	return operationalForensicsCheckID
}

func (OperationalForensicsCheck) Run(_ context.Context, _ model.ExecutionContext, snapshot model.Snapshot) (model.CheckResult, error) {
	findings := []model.Finding{}

	for _, app := range snapshot.Apps {
		for _, artifact := range app.Artifacts {
			switch artifact.Kind {
			case model.ArtifactKindWritablePHPFile:
				findings = append(findings, buildWritableArtifactIndicator(app, artifact.Path, "Writable Laravel path contains a PHP file", "Unexpected PHP files inside storage or bootstrap/cache can indicate dropped webshells, unsafe restore artifacts, or deploy drift.", model.SeverityHigh))
			case model.ArtifactKindWritableSymlink:
				findings = append(findings, buildWritableArtifactIndicator(app, artifact.Path, "Writable Laravel path contains a symlink", "Unexpected symlinks inside writable Laravel paths can hide redirect targets, expose private files, or signal post-compromise persistence attempts.", model.SeverityMedium))
			case model.ArtifactKindWritableArchive:
				findings = append(findings, buildWritableArtifactIndicator(app, artifact.Path, "Writable Laravel path contains a dump or archive artifact", "Unexpected dumps or archives in writable runtime paths can expose backups, leak data, or reflect suspicious post-incident staging behavior.", model.SeverityMedium))
			}
		}
	}

	return model.CheckResult{Findings: findings}, nil
}

func buildWritableArtifactIndicator(app model.LaravelApp, pathRecord model.PathRecord, title string, why string, severity model.Severity) model.Finding {
	return model.Finding{
		ID:          buildFindingID(operationalForensicsCheckID, "writable_artifact", pathRecord.AbsolutePath),
		CheckID:     operationalForensicsCheckID,
		Class:       model.FindingClassCompromiseIndicator,
		Severity:    severity,
		Confidence:  model.ConfidencePossible,
		Title:       title,
		Why:         why,
		Remediation: "Investigate when the artifact appeared, who created it, whether it is expected for this deploy workflow, and remove or isolate it if it is unapproved.",
		Evidence:    pathEvidence(pathRecord),
		Affected: []model.Target{
			appTarget(app),
			pathTarget(pathRecord),
		},
	}
}
