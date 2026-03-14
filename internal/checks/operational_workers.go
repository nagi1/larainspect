package checks

import (
	"context"
	"strings"

	"github.com/nagi1/larainspect/internal/model"
)

const workerSchedulerCheckID = "operations.workers"

var _ Check = WorkerSchedulerCheck{}

type WorkerSchedulerCheck struct{}

func init() {
	MustRegister(WorkerSchedulerCheck{})
}

func (WorkerSchedulerCheck) ID() string {
	return workerSchedulerCheckID
}

func (WorkerSchedulerCheck) Description() string {
	return "Inspect queue worker and scheduler process safety."
}

func (WorkerSchedulerCheck) Run(_ context.Context, _ model.ExecutionContext, snapshot model.Snapshot) (model.CheckResult, error) {
	findings := []model.Finding{}
	schedulerRecordsByApp := map[string][]operationalCommandRecord{}

	for _, record := range operationalCommandRecords(snapshot) {
		if staleReleaseFinding, found := buildStaleReleaseWorkerFinding(record, snapshot.Apps); found {
			findings = append(findings, staleReleaseFinding)
		}

		matchedApps := appsForOperationalCommand(snapshot.Apps, record)
		if len(matchedApps) == 0 {
			continue
		}

		if (commandLooksLikeQueueWorker(record.Command) || commandLooksLikeHorizon(record.Command)) && strings.EqualFold(record.RuntimeUser, "root") {
			findings = append(findings, buildRootWorkerFinding(record, matchedApps))
		}

		if commandLooksLikeScheduler(record.Command) {
			for _, app := range matchedApps {
				schedulerRecordsByApp[app.RootPath] = append(schedulerRecordsByApp[app.RootPath], record)
			}

			if strings.EqualFold(record.RuntimeUser, "root") {
				findings = append(findings, buildRootSchedulerFinding(record, matchedApps))
			}
		}
	}

	for _, app := range snapshot.Apps {
		schedulerRecords := schedulerRecordsByApp[app.RootPath]
		if len(schedulerRecords) < 2 {
			continue
		}

		findings = append(findings, buildDuplicateSchedulerFinding(app, schedulerRecords))
	}

	return model.CheckResult{Findings: findings}, nil
}

func buildStaleReleaseWorkerFinding(record operationalCommandRecord, apps []model.LaravelApp) (model.Finding, bool) {
	for _, app := range apps {
		if !app.Deployment.UsesReleaseLayout || app.ResolvedPath == "" {
			continue
		}

		for _, previousRelease := range app.Deployment.PreviousReleases {
			if textMentionsPath([]string{record.WorkingDirectory, record.Command}, previousRelease.AbsolutePath) {
				return model.Finding{
					ID:          buildFindingID(workerSchedulerCheckID, "stale_release_reference", record.SourcePath+"."+previousRelease.AbsolutePath),
					CheckID:     workerSchedulerCheckID,
					Class:       model.FindingClassDirect,
					Severity:    model.SeverityHigh,
					Confidence:  model.ConfidenceConfirmed,
					Title:       "Worker or scheduler still uses an old release path",
					Why:         "If a worker or scheduler still points at an older release, it may keep running stale code or stale configuration after deploy.",
					Remediation: "Point workers and schedulers at the current release path or a stable current/ symlink, then restart them as part of deployment.",
					Evidence:    commandEvidence(record),
					Affected: []model.Target{
						appTarget(app),
						{Type: "path", Path: previousRelease.AbsolutePath},
					},
				}, true
			}
		}
	}

	return model.Finding{}, false
}

func buildRootWorkerFinding(record operationalCommandRecord, apps []model.LaravelApp) model.Finding {
	title := "Queue worker runs as root"
	why := "If a queue job or one of its dependencies is compromised, running the worker as root makes full server compromise much easier."
	if commandLooksLikeHorizon(record.Command) {
		title = "Horizon runs as root"
		why = "If Horizon is compromised while running as root, the attack can reach full server administration much more easily."
	}

	return model.Finding{
		ID:          buildFindingID(workerSchedulerCheckID, "root_worker", record.SourcePath+"."+record.Name),
		CheckID:     workerSchedulerCheckID,
		Class:       model.FindingClassDirect,
		Severity:    model.SeverityCritical,
		Confidence:  model.ConfidenceConfirmed,
		Title:       title,
		Why:         why,
		Remediation: "Run queue workers and Horizon under the intended non-root app user, and keep deploy or administration work on separate accounts.",
		Evidence:    commandEvidence(record),
		Affected:    compactAppTargets(apps),
	}
}

func buildRootSchedulerFinding(record operationalCommandRecord, apps []model.LaravelApp) model.Finding {
	return model.Finding{
		ID:          buildFindingID(workerSchedulerCheckID, "root_scheduler", record.SourcePath+"."+record.Name),
		CheckID:     workerSchedulerCheckID,
		Class:       model.FindingClassDirect,
		Severity:    model.SeverityCritical,
		Confidence:  model.ConfidenceConfirmed,
		Title:       "Laravel scheduler runs as root",
		Why:         "If scheduled tasks run as root, they can leave behind root-owned files and make mistakes or abuse much more damaging.",
		Remediation: "Run schedule:run or schedule:work as the intended app or deploy user, not root.",
		Evidence:    commandEvidence(record),
		Affected:    compactAppTargets(apps),
	}
}

func buildDuplicateSchedulerFinding(app model.LaravelApp, records []operationalCommandRecord) model.Finding {
	evidence := []model.Evidence{
		{Label: "app", Detail: app.RootPath},
	}
	for _, record := range records {
		evidence = append(evidence, commandEvidence(record)...)
	}

	return model.Finding{
		ID:          buildFindingID(workerSchedulerCheckID, "duplicate_scheduler", app.RootPath),
		CheckID:     workerSchedulerCheckID,
		Class:       model.FindingClassDirect,
		Severity:    model.SeverityHigh,
		Confidence:  model.ConfidenceConfirmed,
		Title:       "Laravel app has more than one scheduler configured",
		Why:         "If more than one scheduler is active, the same job may run multiple times and create confusing behavior during normal operation or incidents.",
		Remediation: "Keep exactly one production scheduler definition per Laravel app and remove duplicate cron, systemd, or Supervisor entries.",
		Evidence:    evidence,
		Affected: []model.Target{
			appTarget(app),
		},
	}
}
