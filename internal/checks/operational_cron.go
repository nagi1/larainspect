package checks

import (
	"context"
	"strings"

	"github.com/nagi1/larainspect/internal/model"
)

const operationalCronCheckID = "operations.cron"

type OperationalCronCheck struct{}

func init() {
	MustRegister(OperationalCronCheck{})
}

func (OperationalCronCheck) ID() string {
	return operationalCronCheckID
}

func (OperationalCronCheck) Run(_ context.Context, _ model.ExecutionContext, snapshot model.Snapshot) (model.CheckResult, error) {
	findings := []model.Finding{}

	for _, record := range operationalCommandRecords(snapshot) {
		matchedApps := appsForOperationalCommand(snapshot.Apps, record)
		if len(matchedApps) == 0 || record.SourceType != "cron" {
			continue
		}

		if commandLooksLikeDirectArtisanTask(record.Command) {
			findings = append(findings, buildDirectArtisanCronFinding(record, matchedApps))
		}

		for _, app := range matchedApps {
			if commandRedirectsToPublicPath(record, app) {
				findings = append(findings, buildPublicCronOutputFinding(record, app))
			}

			if commandLooksLikeBackupOrDump(record.Command) && commandMentionsPublicArchivePath(record, app) {
				findings = append(findings, buildPublicBackupArtifactFinding(record, app))
			}
		}

		if (commandLooksLikeBackupOrDump(record.Command) || commandLooksLikeRestoreWorkflow(record.Command) || commandLooksLikeArtisanMaintenance(record.Command)) &&
			strings.EqualFold(record.RuntimeUser, "root") {
			findings = append(findings, buildRootMaintenanceCronFinding(record, matchedApps))
		}
	}

	return model.CheckResult{Findings: findings}, nil
}

func buildDirectArtisanCronFinding(record operationalCommandRecord, apps []model.LaravelApp) model.Finding {
	return model.Finding{
		ID:          buildFindingID(operationalCronCheckID, "direct_artisan_job", record.SourcePath+"."+record.Name),
		CheckID:     operationalCronCheckID,
		Class:       model.FindingClassHeuristic,
		Severity:    model.SeverityMedium,
		Confidence:  model.ConfidenceProbable,
		Title:       "Cron runs artisan commands directly outside the scheduler baseline",
		Why:         "Direct artisan cron jobs are harder to reason about than a single scheduler entry and commonly introduce duplicate task execution, drift, or unreviewed maintenance commands.",
		Remediation: "Prefer one schedule:run baseline per app and move recurring Laravel tasks into the framework scheduler unless there is a specific reason not to.",
		Evidence:    commandEvidence(record),
		Affected:    compactAppTargets(apps),
	}
}

func buildPublicCronOutputFinding(record operationalCommandRecord, app model.LaravelApp) model.Finding {
	return model.Finding{
		ID:          buildFindingID(operationalCronCheckID, "public_output", record.SourcePath+"."+app.RootPath),
		CheckID:     operationalCronCheckID,
		Class:       model.FindingClassDirect,
		Severity:    model.SeverityHigh,
		Confidence:  model.ConfidenceConfirmed,
		Title:       "Cron command writes output into a public path",
		Why:         "Cron output redirected into a served path can leak stack traces, secrets, dump data, or maintenance output directly to web clients.",
		Remediation: "Redirect cron output to a secure non-public log path or suppress it intentionally after validating the command behavior.",
		Evidence:    append(commandEvidence(record), model.Evidence{Label: "app", Detail: app.RootPath}),
		Affected: []model.Target{
			appTarget(app),
		},
	}
}

func buildPublicBackupArtifactFinding(record operationalCommandRecord, app model.LaravelApp) model.Finding {
	return model.Finding{
		ID:          buildFindingID(operationalCronCheckID, "public_backup_artifact", record.SourcePath+"."+app.RootPath),
		CheckID:     operationalCronCheckID,
		Class:       model.FindingClassDirect,
		Severity:    model.SeverityHigh,
		Confidence:  model.ConfidenceConfirmed,
		Title:       "Backup or dump workflow targets a public path",
		Why:         "Backups, dumps, or archives placed under the public tree can expose source, database contents, and credentials directly over the web boundary.",
		Remediation: "Write backups outside served paths, keep them tightly permissioned, and separate backup destinations from the Laravel docroot completely.",
		Evidence:    append(commandEvidence(record), model.Evidence{Label: "app", Detail: app.RootPath}),
		Affected: []model.Target{
			appTarget(app),
		},
	}
}

func buildRootMaintenanceCronFinding(record operationalCommandRecord, apps []model.LaravelApp) model.Finding {
	return model.Finding{
		ID:          buildFindingID(operationalCronCheckID, "root_maintenance", record.SourcePath+"."+record.Name),
		CheckID:     operationalCronCheckID,
		Class:       model.FindingClassDirect,
		Severity:    model.SeverityHigh,
		Confidence:  model.ConfidenceConfirmed,
		Title:       "Cron runs backup, restore, or maintenance work as root",
		Why:         "Root-run backup, restore, or artisan maintenance commands commonly create ownership drift and widen the blast radius of routine Laravel operations.",
		Remediation: "Run backup, restore, and Laravel maintenance commands as the intended deploy or app user, and keep root limited to narrow host-administration tasks only.",
		Evidence:    commandEvidence(record),
		Affected:    compactAppTargets(apps),
	}
}
