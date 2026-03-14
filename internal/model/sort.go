package model

import "sort"

// sortByKey sorts a slice by a single string key extracted from each element.
func sortByKey[T any](slice []T, key func(T) string) {
	sort.Slice(slice, func(i, j int) bool {
		return key(slice[i]) < key(slice[j])
	})
}

// sortByTwoKeys sorts a slice by a primary then secondary string key.
func sortByTwoKeys[T any](slice []T, primary func(T) string, secondary func(T) string) {
	sort.Slice(slice, func(i, j int) bool {
		pi, pj := primary(slice[i]), primary(slice[j])
		if pi != pj {
			return pi < pj
		}
		return secondary(slice[i]) < secondary(slice[j])
	})
}

// sortByThreeKeys sorts a slice by primary, secondary, then tertiary string key.
func sortByThreeKeys[T any](slice []T, k1, k2, k3 func(T) string) {
	sort.Slice(slice, func(i, j int) bool {
		if a, b := k1(slice[i]), k1(slice[j]); a != b {
			return a < b
		}
		if a, b := k2(slice[i]), k2(slice[j]); a != b {
			return a < b
		}
		return k3(slice[i]) < k3(slice[j])
	})
}

func SortPackageRecords(records []PackageRecord) {
	sortByTwoKeys(records,
		func(r PackageRecord) string { return r.Name },
		func(r PackageRecord) string { return r.Source },
	)
}

func SortPathRecords(records []PathRecord) {
	sortByKey(records, func(r PathRecord) string { return r.RelativePath })
}

func SortArtifactRecords(records []ArtifactRecord) {
	sortByKey(records, func(r ArtifactRecord) string { return r.Path.RelativePath })
}

func SortSourceMatches(matches []SourceMatch) {
	sort.Slice(matches, func(i, j int) bool {
		a, b := matches[i], matches[j]
		if a.RelativePath != b.RelativePath {
			return a.RelativePath < b.RelativePath
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.RuleID < b.RuleID
	})
}

func SortNginxSites(sites []NginxSite) {
	sortByTwoKeys(sites,
		func(s NginxSite) string { return s.ConfigPath },
		func(s NginxSite) string { return s.Root },
	)
}

func SortPHPFPMPools(pools []PHPFPMPool) {
	sortByTwoKeys(pools,
		func(p PHPFPMPool) string { return p.ConfigPath },
		func(p PHPFPMPool) string { return p.Name },
	)
}

func SortMySQLConfigs(configs []MySQLConfig) {
	sortByTwoKeys(configs,
		func(c MySQLConfig) string { return c.ConfigPath },
		func(c MySQLConfig) string { return c.Section },
	)
}

func SortSupervisorPrograms(programs []SupervisorProgram) {
	sortByTwoKeys(programs,
		func(p SupervisorProgram) string { return p.ConfigPath },
		func(p SupervisorProgram) string { return p.Name },
	)
}

func SortSupervisorHTTPServers(servers []SupervisorHTTPServer) {
	sortByTwoKeys(servers,
		func(s SupervisorHTTPServer) string { return s.ConfigPath },
		func(s SupervisorHTTPServer) string { return s.Bind },
	)
}

func SortSystemdUnits(units []SystemdUnit) {
	sortByTwoKeys(units,
		func(u SystemdUnit) string { return u.Path },
		func(u SystemdUnit) string { return u.Name },
	)
}

func SortCronEntries(entries []CronEntry) {
	sortByThreeKeys(entries,
		func(e CronEntry) string { return e.SourcePath },
		func(e CronEntry) string { return e.Schedule },
		func(e CronEntry) string { return e.Command },
	)
}

func SortListenerRecords(records []ListenerRecord) {
	sortByThreeKeys(records,
		func(r ListenerRecord) string { return r.Protocol },
		func(r ListenerRecord) string { return r.LocalPort },
		func(r ListenerRecord) string { return r.LocalAddress },
	)
}

func SortSSHConfigs(configs []SSHConfig) {
	sortByKey(configs, func(c SSHConfig) string { return c.Path })
}

func SortSSHAccounts(accounts []SSHAccount) {
	sortByTwoKeys(accounts,
		func(a SSHAccount) string { return a.HomePath },
		func(a SSHAccount) string { return a.User },
	)
}

func SortSudoRules(rules []SudoRule) {
	sortByTwoKeys(rules,
		func(r SudoRule) string { return r.Path },
		func(r SudoRule) string { return r.Principal },
	)
}

func SortFirewallSummaries(summaries []FirewallSummary) {
	sortByKey(summaries, func(s FirewallSummary) string { return s.Source })
}
