package checks

import (
	"context"
	"strings"

	"github.com/nagi1/larainspect/internal/model"
)

const operationalCronCheckID = "operations.cron"

var _ Check = OperationalCronCheck{}

type OperationalCronCheck struct{}

func init() {
	MustRegister(OperationalCronCheck{})
}

func (OperationalCronCheck) ID() string {
	return operationalCronCheckID
}

func (OperationalCronCheck) Description() string {
	return "Inspect cron and scheduler definitions for unsafe Laravel operations."
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
		Title:       "Cron runs Laravel commands directly instead of using the scheduler",
		Why:         "Direct Artisan cron jobs are harder to review than one scheduler entry and often lead to duplicate tasks or untracked maintenance commands.",
		Remediation: "Prefer one schedule:run baseline per app and move recurring Laravel tasks into the framework scheduler unless you have a specific documented reason not to.",
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
		Title:       "Cron writes command output into a public web path",
		Why:         "If cron output is written into a served path, stack traces, secrets, and maintenance output may become visible in the browser.",
		Remediation: "Write cron output to a secure non-public log path, or suppress it intentionally after you confirm the command behaves safely.",
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
		Title:       "Backups are written into a public web path",
		Why:         "If backups, dumps, or archives land under the public tree, source code, database contents, or credentials may be exposed over the web.",
		Remediation: "Write backups outside served paths, keep them tightly permissioned, and separate backup destinations completely from the Laravel web root.",
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
		Title:       "Cron runs backup, restore, or maintenance commands as root",
		Why:         "Running these jobs as root often leaves behind root-owned files and makes routine Laravel operations more dangerous than they need to be.",
		Remediation: "Run backup, restore, and Laravel maintenance commands as the intended deploy or app user, and reserve root for narrow host administration tasks only.",
		Evidence:    commandEvidence(record),
		Affected:    compactAppTargets(apps),
	}
}
