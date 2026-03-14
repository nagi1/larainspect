package checks

import "github.com/nagi1/larainspect/internal/model"

func buildSourceFinding(
	checkID string,
	suffix string,
	app model.LaravelApp,
	class model.FindingClass,
	severity model.Severity,
	confidence model.Confidence,
	title string,
	why string,
	remediation string,
	sourceMatches []model.SourceMatch,
	additionalEvidence []model.Evidence,
) model.Finding {
	evidence := []model.Evidence{}
	affected := []model.Target{appTarget(app)}
	seenAffectedPaths := map[string]struct{}{
		app.RootPath: {},
	}

	for _, sourceMatch := range sourceMatches {
		evidence = append(evidence, sourceMatchEvidence(app, sourceMatch)...)

		target := sourceMatchTarget(app, sourceMatch)
		if _, seen := seenAffectedPaths[target.Path]; seen {
			continue
		}
		seenAffectedPaths[target.Path] = struct{}{}
		affected = append(affected, target)
	}

	evidence = append(evidence, additionalEvidence...)

	return model.Finding{
		ID:          buildFindingID(checkID, suffix, app.RootPath),
		CheckID:     checkID,
		Class:       class,
		Severity:    severity,
		Confidence:  confidence,
		Title:       title,
		Why:         why,
		Remediation: remediation,
		Evidence:    evidence,
		Affected:    affected,
	}
}

// ruleMetadata resolves severity, confidence, title, why, and remediation from
// a loaded rule definition, falling back to the provided defaults when the rule
// is not found (e.g. it was disabled or removed by config).
func ruleMetadata(
	snapshot model.Snapshot,
	ruleID string,
	fallbackSeverity model.Severity,
	fallbackConfidence model.Confidence,
	fallbackTitle string,
	fallbackWhy string,
	fallbackRemediation string,
) (model.Severity, model.Confidence, string, string, string) {
	rule, found := snapshot.RuleDefinitions[ruleID]
	if !found {
		return fallbackSeverity, fallbackConfidence, fallbackTitle, fallbackWhy, fallbackRemediation
	}

	severity := rule.Severity
	if !severity.Valid() {
		severity = fallbackSeverity
	}

	confidence := rule.EffectiveConfidence()

	title := rule.Title
	if title == "" {
		title = fallbackTitle
	}

	why := rule.Why
	if why == "" {
		why = fallbackWhy
	}

	remediation := rule.Remediation
	if remediation == "" {
		remediation = fallbackRemediation
	}

	return severity, confidence, title, why, remediation
}

func appendSourceMatches(groups ...[]model.SourceMatch) []model.SourceMatch {
	total := 0
	for _, group := range groups {
		total += len(group)
	}

	merged := make([]model.SourceMatch, 0, total)
	for _, group := range groups {
		merged = append(merged, group...)
	}

	return merged
}
