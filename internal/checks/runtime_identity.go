package checks

import (
	"strings"

	"github.com/nagi1/larainspect/internal/model"
)

type appRuntimeIdentities struct {
	Users  []string
	Groups []string
	Pools  []model.PHPFPMPool
}

func collectAppRuntimeIdentities(app model.LaravelApp, snapshot model.Snapshot, config model.AuditConfig) appRuntimeIdentities {
	identities := appRuntimeIdentities{
		Users:  []string{},
		Groups: []string{},
		Pools:  matchedPHPFPMPoolsForApp(app, snapshot.NginxSites, snapshot.PHPFPMPools),
	}

	for _, user := range config.NormalizedRuntimeUsers() {
		identities.Users = appendNormalizedUnique(identities.Users, user)
	}
	for _, group := range config.NormalizedRuntimeGroups() {
		identities.Groups = appendNormalizedUnique(identities.Groups, group)
	}

	for _, pool := range identities.Pools {
		identities.Users = appendNormalizedUnique(identities.Users, pool.User)
		identities.Groups = appendNormalizedUnique(identities.Groups, pool.Group)
	}

	for _, record := range operationalCommandRecords(snapshot) {
		if !commandLooksLikeQueueWorker(record.Command) &&
			!commandLooksLikeHorizon(record.Command) &&
			!commandLooksLikeScheduler(record.Command) {
			continue
		}

		for _, matchedApp := range appsForOperationalCommand(snapshot.Apps, record) {
			if matchedApp.RootPath != app.RootPath {
				continue
			}

			identities.Users = appendNormalizedUnique(identities.Users, record.RuntimeUser)
			break
		}
	}

	return identities
}

func matchedPHPFPMPoolsForApp(app model.LaravelApp, nginxSites []model.NginxSite, pools []model.PHPFPMPool) []model.PHPFPMPool {
	matchedPools := []model.PHPFPMPool{}
	targetSet := map[string]struct{}{}

	for _, target := range fastCGITargetsForApp(app, nginxSites) {
		targetSet[target] = struct{}{}
	}

	for _, pool := range pools {
		normalizedTarget := normalizeFastCGITarget(pool.Listen)
		if normalizedTarget == "" {
			continue
		}

		if _, found := targetSet[normalizedTarget]; !found {
			continue
		}

		matchedPools = append(matchedPools, pool)
	}

	if len(matchedPools) == 0 && len(pools) == 1 && len(nginxSites) == 0 {
		return append(matchedPools, pools[0])
	}

	return matchedPools
}

func appendNormalizedUnique(values []string, rawValue string) []string {
	normalizedValue := strings.TrimSpace(rawValue)
	if normalizedValue == "" || stringSliceContainsFold(values, normalizedValue) {
		return values
	}

	return append(values, normalizedValue)
}

func pathWritableByRuntimeIdentity(pathRecord model.PathRecord, identities appRuntimeIdentities) bool {
	if !pathRecord.Inspected || !pathRecord.Exists {
		return false
	}

	if pathRecord.IsWorldWritable() {
		return true
	}

	if pathRecord.IsOwnerWritable() && stringSliceContainsFold(identities.Users, strings.TrimSpace(pathRecord.OwnerName)) {
		return true
	}

	if pathRecord.IsGroupWritable() && stringSliceContainsFold(identities.Groups, strings.TrimSpace(pathRecord.GroupName)) {
		return true
	}

	return false
}
