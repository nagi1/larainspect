package checks

import (
	"slices"
	"strings"

	"github.com/nagi1/larainspect/internal/model"
)

func buildHeuristicFindingForSourceMatches(
	suffix string,
	app model.LaravelApp,
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
	idPaths := []string{app.RootPath}
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
		idPaths = append(idPaths, target.Path)
	}

	evidence = append(evidence, additionalEvidence...)
	slices.Sort(idPaths)

	return model.Finding{
		ID:          buildFindingID(frameworkHeuristicsCheckID, suffix, strings.Join(idPaths, "|")),
		CheckID:     frameworkHeuristicsCheckID,
		Class:       model.FindingClassHeuristic,
		Severity:    severity,
		Confidence:  confidence,
		Title:       title,
		Why:         why,
		Remediation: remediation,
		Evidence:    evidence,
		Affected:    affected,
	}
}
