package checks

import (
	"strings"

	"github.com/nagi1/larainspect/internal/model"
)

type observedNginxSocketBoundaryIdentities struct {
	Users   []string
	Groups  []string
	Sources []string
}

func buildObservedNginxSocketBoundaryFinding(pool model.PHPFPMPool, nginxSites []model.NginxSite, identities observedNginxSocketBoundaryIdentities) (model.Finding, bool) {
	if !poolUsesUnixSocket(pool.Listen) {
		return model.Finding{}, false
	}
	if len(identities.Users) == 0 && len(identities.Groups) == 0 {
		return model.Finding{}, false
	}
	if strings.TrimSpace(pool.ListenOwner) == "" || strings.TrimSpace(pool.ListenGroup) == "" {
		return model.Finding{}, false
	}

	socketMode, ok := socketBoundaryMode(pool)
	if !ok {
		return model.Finding{}, false
	}

	matchedSites := matchedNginxSitesForPool(pool, nginxSites)
	if len(matchedSites) == 0 || socketACLAllowsObservedNginxIdentity(pool, socketMode, identities) {
		return model.Finding{}, false
	}

	evidence := []model.Evidence{
		{Label: "config", Detail: pool.ConfigPath},
		{Label: "pool", Detail: pool.Name},
		{Label: "listen", Detail: pool.Listen},
		{Label: "listen_owner", Detail: pool.ListenOwner},
		{Label: "listen_group", Detail: pool.ListenGroup},
		{Label: "mode", Detail: pool.ListenMode},
	}
	for _, site := range matchedSites {
		evidence = append(evidence, model.Evidence{Label: "nginx_site", Detail: site.ConfigPath})
	}
	for _, source := range identities.Sources {
		evidence = append(evidence, model.Evidence{Label: "nginx_unit", Detail: source})
	}
	for _, user := range identities.Users {
		evidence = append(evidence, model.Evidence{Label: "nginx_user", Detail: user})
	}
	for _, group := range identities.Groups {
		evidence = append(evidence, model.Evidence{Label: "nginx_group", Detail: group})
	}

	return model.Finding{
		ID:          buildFindingID(phpFPMSecurityCheckID, "socket_acl_not_aligned", pool.ConfigPath+"."+pool.Name),
		CheckID:     phpFPMSecurityCheckID,
		Class:       model.FindingClassHeuristic,
		Severity:    model.SeverityMedium,
		Confidence:  model.ConfidenceProbable,
		Title:       "Web server user does not match PHP-FPM socket permissions",
		Why:         "The configured socket owner, group, or mode does not match the Nginx user or group Larainspect observed, so the web server may not be the only process that can reach PHP-FPM or it may not be able to reach it cleanly.",
		Remediation: "Set listen.owner, listen.group, and listen.mode to match the exact web server identity that should connect to PHP-FPM, and keep that separate from the PHP runtime account when practical.",
		Evidence:    evidence,
		Affected: []model.Target{
			{Type: "path", Path: pool.ConfigPath},
		},
	}, true
}

func collectObservedNginxSocketBoundaryIdentities(units []model.SystemdUnit) observedNginxSocketBoundaryIdentities {
	identities := observedNginxSocketBoundaryIdentities{
		Users:   []string{},
		Groups:  []string{},
		Sources: []string{},
	}

	for _, unit := range units {
		if !systemdUnitLooksLikeNginxFrontend(unit) {
			continue
		}

		if socketBoundaryIdentityLooksUsable(unit.User) {
			identities.Users = appendNormalizedUnique(identities.Users, unit.User)
		}
		if socketBoundaryIdentityLooksUsable(unit.Group) {
			identities.Groups = appendNormalizedUnique(identities.Groups, unit.Group)
		}
		if strings.TrimSpace(unit.Path) != "" {
			identities.Sources = appendNormalizedUnique(identities.Sources, unit.Path)
		}
	}

	return identities
}

func systemdUnitLooksLikeNginxFrontend(unit model.SystemdUnit) bool {
	normalizedName := strings.ToLower(strings.TrimSpace(unit.Name))
	normalizedCommand := strings.ToLower(strings.TrimSpace(unit.ExecStart))
	return strings.Contains(normalizedName, "nginx") || strings.Contains(normalizedCommand, "nginx")
}

func socketBoundaryIdentityLooksUsable(identity string) bool {
	normalizedIdentity := strings.TrimSpace(identity)
	if normalizedIdentity == "" {
		return false
	}

	return !strings.EqualFold(normalizedIdentity, "root")
}

func matchedNginxSitesForPool(pool model.PHPFPMPool, nginxSites []model.NginxSite) []model.NginxSite {
	poolTarget := normalizeFastCGITarget(pool.Listen)
	if poolTarget == "" {
		return nil
	}

	matchedSites := []model.NginxSite{}
	for _, site := range nginxSites {
		for _, target := range site.FastCGIPassTargets {
			if normalizeFastCGITarget(target) != poolTarget {
				continue
			}

			matchedSites = append(matchedSites, site)
			break
		}
	}

	return matchedSites
}

func socketBoundaryMode(pool model.PHPFPMPool) (uint32, bool) {
	if strings.TrimSpace(pool.ListenMode) == "" {
		return 0, false
	}

	return parseOctalMode(pool.ListenMode)
}

func socketACLAllowsObservedNginxIdentity(pool model.PHPFPMPool, mode uint32, identities observedNginxSocketBoundaryIdentities) bool {
	if mode&0o002 != 0 {
		return true
	}

	if mode&0o200 != 0 && stringSliceContainsFold(identities.Users, pool.ListenOwner) {
		return true
	}

	if mode&0o020 != 0 && stringSliceContainsFold(identities.Groups, pool.ListenGroup) {
		return true
	}

	return false
}

func stringSliceContainsFold(values []string, candidate string) bool {
	trimmedCandidate := strings.TrimSpace(candidate)
	if trimmedCandidate == "" {
		return false
	}

	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), trimmedCandidate) {
			return true
		}
	}

	return false
}
