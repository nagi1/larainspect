package checks

import (
	"context"
	"path/filepath"
	"slices"
	"strings"

	"github.com/nagi1/larainspect/internal/model"
)

const phpFPMSecurityCheckID = "phpfpm.security"

var _ Check = PHPFPMSecurityCheck{}

type PHPFPMSecurityCheck struct{}

func init() {
	MustRegister(PHPFPMSecurityCheck{})
}

func (PHPFPMSecurityCheck) ID() string {
	return phpFPMSecurityCheckID
}

func (PHPFPMSecurityCheck) Description() string {
	return "Inspect PHP-FPM pool isolation, socket, and runtime hardening settings."
}

func (PHPFPMSecurityCheck) Run(_ context.Context, execution model.ExecutionContext, snapshot model.Snapshot) (model.CheckResult, error) {
	findings := []model.Finding{}
	observedNginxIdentities := collectObservedNginxSocketBoundaryIdentities(snapshot.SystemdUnits, execution.Config)

	for _, pool := range snapshot.PHPFPMPools {
		if rootPoolFinding, found := buildRootPoolFinding(pool); found {
			findings = append(findings, rootPoolFinding)
		}

		if loopbackTCPFinding, found := buildLoopbackTCPPoolFinding(pool); found {
			findings = append(findings, loopbackTCPFinding)
		}

		if exposedTCPFinding, found := buildExposedTCPPoolFinding(pool); found {
			findings = append(findings, exposedTCPFinding)
		}

		if inheritedEnvironmentFinding, found := buildInheritedEnvironmentFinding(pool); found {
			findings = append(findings, inheritedEnvironmentFinding)
		}

		if socketModeFinding, found := buildBroadSocketModeFinding(pool); found {
			findings = append(findings, socketModeFinding)
		}

		if socketACLFinding, found := buildMissingSocketACLFinding(pool); found {
			findings = append(findings, socketACLFinding)
		}

		if collapsedSocketBoundaryFinding, found := buildCollapsedSocketBoundaryFinding(pool); found {
			findings = append(findings, collapsedSocketBoundaryFinding)
		}

		if nginxBoundaryFinding, found := buildObservedNginxSocketBoundaryFinding(pool, snapshot.NginxSites, observedNginxIdentities); found {
			findings = append(findings, nginxBoundaryFinding)
		}
	}

	for _, sharedPoolFinding := range buildSharedPoolFindings(snapshot.Apps, snapshot.NginxSites, snapshot.PHPFPMPools) {
		findings = append(findings, sharedPoolFinding)
	}

	for _, sharedRuntimeUserFinding := range buildSharedRuntimeUserFindings(snapshot.Apps, snapshot.NginxSites, snapshot.PHPFPMPools) {
		findings = append(findings, sharedRuntimeUserFinding)
	}

	for _, app := range snapshot.Apps {
		findings = append(findings, buildContextualPHPRuntimeFindings(app, snapshot)...)
	}

	return model.CheckResult{Findings: findings}, nil
}

func buildInheritedEnvironmentFinding(pool model.PHPFPMPool) (model.Finding, bool) {
	if !strings.EqualFold(strings.TrimSpace(pool.ClearEnv), "no") {
		return model.Finding{}, false
	}

	return model.Finding{
		ID:          buildFindingID(phpFPMSecurityCheckID, "clear_env_disabled", pool.ConfigPath+"."+pool.Name),
		CheckID:     phpFPMSecurityCheckID,
		Class:       model.FindingClassDirect,
		Severity:    model.SeverityLow,
		Confidence:  model.ConfidenceConfirmed,
		Title:       "PHP-FPM workers inherit the parent service environment",
		Why:         "If clear_env is disabled, PHP workers inherit extra environment variables from the parent service, which can expose secrets or make runtime behavior harder to understand.",
		Remediation: "Leave clear_env enabled by default and pass only the specific environment variables the app actually needs.",
		Evidence: []model.Evidence{
			{Label: "config", Detail: pool.ConfigPath},
			{Label: "pool", Detail: pool.Name},
			{Label: "clear_env", Detail: pool.ClearEnv},
		},
		Affected: []model.Target{
			{Type: "path", Path: pool.ConfigPath},
		},
	}, true
}

func buildRootPoolFinding(pool model.PHPFPMPool) (model.Finding, bool) {
	if !strings.EqualFold(strings.TrimSpace(pool.User), "root") {
		return model.Finding{}, false
	}

	return model.Finding{
		ID:          buildFindingID(phpFPMSecurityCheckID, "root_pool", pool.ConfigPath+"."+pool.Name),
		CheckID:     phpFPMSecurityCheckID,
		Class:       model.FindingClassDirect,
		Severity:    model.SeverityCritical,
		Confidence:  model.ConfidenceConfirmed,
		Title:       "PHP-FPM is running this app as root",
		Why:         "If the app or one of its dependencies is compromised, the attacker gets root-level access much more easily instead of being contained to an app user.",
		Remediation: "Run each PHP-FPM pool as a dedicated non-root user and give it access only to the files Laravel actually needs.",
		Evidence: []model.Evidence{
			{Label: "config", Detail: pool.ConfigPath},
			{Label: "pool", Detail: pool.Name},
			{Label: "user", Detail: pool.User},
		},
		Affected: []model.Target{
			{Type: "path", Path: pool.ConfigPath},
		},
	}, true
}

func buildExposedTCPPoolFinding(pool model.PHPFPMPool) (model.Finding, bool) {
	if !poolListensOnBroadTCP(pool.Listen) {
		return model.Finding{}, false
	}

	return model.Finding{
		ID:          buildFindingID(phpFPMSecurityCheckID, "broad_tcp_listener", pool.ConfigPath+"."+pool.Name),
		CheckID:     phpFPMSecurityCheckID,
		Class:       model.FindingClassDirect,
		Severity:    model.SeverityHigh,
		Confidence:  model.ConfidenceConfirmed,
		Title:       "PHP-FPM is listening on a broad network address",
		Why:         "A broadly bound PHP-FPM port can be reached from other hosts or networks, which exposes the PHP runtime directly instead of keeping it behind the local web server.",
		Remediation: "Prefer a Unix socket for local Nginx-to-PHP traffic. If TCP is required, bind PHP-FPM to 127.0.0.1 or a tightly scoped private address only.",
		Evidence: []model.Evidence{
			{Label: "config", Detail: pool.ConfigPath},
			{Label: "pool", Detail: pool.Name},
			{Label: "listen", Detail: pool.Listen},
		},
		Affected: []model.Target{
			{Type: "path", Path: pool.ConfigPath},
		},
	}, true
}

func buildLoopbackTCPPoolFinding(pool model.PHPFPMPool) (model.Finding, bool) {
	if !poolListensOnLoopbackTCP(pool.Listen) {
		return model.Finding{}, false
	}

	return model.Finding{
		ID:          buildFindingID(phpFPMSecurityCheckID, "loopback_tcp_listener", pool.ConfigPath+"."+pool.Name),
		CheckID:     phpFPMSecurityCheckID,
		Class:       model.FindingClassHeuristic,
		Severity:    model.SeverityMedium,
		Confidence:  model.ConfidenceProbable,
		Title:       "PHP-FPM uses a local TCP port instead of a Unix socket",
		Why:         "A loopback TCP port is safer than a public port, but it still exposes PHP-FPM through the local network stack instead of a tightly permissioned socket file.",
		Remediation: "Prefer a Unix socket with an explicit owner, group, and owner-only access pattern such as 0660 unless TCP is required for a documented reason.",
		Evidence: []model.Evidence{
			{Label: "config", Detail: pool.ConfigPath},
			{Label: "pool", Detail: pool.Name},
			{Label: "listen", Detail: pool.Listen},
		},
		Affected: []model.Target{
			{Type: "path", Path: pool.ConfigPath},
		},
	}, true
}

func buildBroadSocketModeFinding(pool model.PHPFPMPool) (model.Finding, bool) {
	if !poolUsesUnixSocket(pool.Listen) || strings.TrimSpace(pool.ListenMode) == "" {
		return model.Finding{}, false
	}

	listenMode, ok := parseOctalMode(pool.ListenMode)
	if !ok || !socketModeExceedsBoundary(listenMode) {
		return model.Finding{}, false
	}

	return model.Finding{
		ID:          buildFindingID(phpFPMSecurityCheckID, "broad_socket_mode", pool.ConfigPath+"."+pool.Name),
		CheckID:     phpFPMSecurityCheckID,
		Class:       model.FindingClassDirect,
		Severity:    model.SeverityHigh,
		Confidence:  model.ConfidenceConfirmed,
		Title:       "PHP-FPM socket is accessible to more users than needed",
		Why:         "If the socket file is too open, users or groups other than the web server may be able to send requests to PHP-FPM.",
		Remediation: "Limit the socket to the web server user and group only, usually with owner/group access such as 0660.",
		Evidence: []model.Evidence{
			{Label: "config", Detail: pool.ConfigPath},
			{Label: "pool", Detail: pool.Name},
			{Label: "listen", Detail: pool.Listen},
			{Label: "mode", Detail: pool.ListenMode},
		},
		Affected: []model.Target{
			{Type: "path", Path: pool.ConfigPath},
		},
	}, true
}

func buildMissingSocketACLFinding(pool model.PHPFPMPool) (model.Finding, bool) {
	if !poolUsesUnixSocket(pool.Listen) {
		return model.Finding{}, false
	}

	if strings.TrimSpace(pool.ListenOwner) != "" && strings.TrimSpace(pool.ListenGroup) != "" {
		return model.Finding{}, false
	}

	return model.Finding{
		ID:          buildFindingID(phpFPMSecurityCheckID, "missing_socket_acl", pool.ConfigPath+"."+pool.Name),
		CheckID:     phpFPMSecurityCheckID,
		Class:       model.FindingClassHeuristic,
		Severity:    model.SeverityMedium,
		Confidence:  model.ConfidenceProbable,
		Title:       "PHP-FPM socket owner and group are not set explicitly",
		Why:         "If the socket owner and group are not set directly, it is easier for the web-server-to-PHP access boundary to drift over time.",
		Remediation: "Set both listen.owner and listen.group explicitly for each PHP-FPM socket, and keep them limited to the web server identity that needs access.",
		Evidence: []model.Evidence{
			{Label: "config", Detail: pool.ConfigPath},
			{Label: "pool", Detail: pool.Name},
			{Label: "listen", Detail: pool.Listen},
			{Label: "listen_owner", Detail: pool.ListenOwner},
			{Label: "listen_group", Detail: pool.ListenGroup},
		},
		Affected: []model.Target{
			{Type: "path", Path: pool.ConfigPath},
		},
	}, true
}

func buildCollapsedSocketBoundaryFinding(pool model.PHPFPMPool) (model.Finding, bool) {
	if !poolUsesUnixSocket(pool.Listen) {
		return model.Finding{}, false
	}
	if strings.TrimSpace(pool.ListenOwner) == "" || strings.TrimSpace(pool.ListenGroup) == "" {
		return model.Finding{}, false
	}
	if !socketACLMatchesRuntimeIdentity(pool) {
		return model.Finding{}, false
	}

	return model.Finding{
		ID:          buildFindingID(phpFPMSecurityCheckID, "collapsed_socket_boundary", pool.ConfigPath+"."+pool.Name),
		CheckID:     phpFPMSecurityCheckID,
		Class:       model.FindingClassHeuristic,
		Severity:    model.SeverityMedium,
		Confidence:  model.ConfidenceProbable,
		Title:       "PHP-FPM socket uses the same user or group as the PHP runtime",
		Why:         "When the socket matches the PHP runtime user or group, more local PHP-side processes may be able to connect than intended, not just the web server.",
		Remediation: "Set the socket owner and group to the exact web server identity that should reach PHP-FPM instead of reusing the PHP runtime account by default.",
		Evidence: []model.Evidence{
			{Label: "config", Detail: pool.ConfigPath},
			{Label: "pool", Detail: pool.Name},
			{Label: "listen", Detail: pool.Listen},
			{Label: "runtime_user", Detail: pool.User},
			{Label: "runtime_group", Detail: pool.Group},
			{Label: "listen_owner", Detail: pool.ListenOwner},
			{Label: "listen_group", Detail: pool.ListenGroup},
		},
		Affected: []model.Target{
			{Type: "path", Path: pool.ConfigPath},
		},
	}, true
}

func buildSharedPoolFindings(apps []model.LaravelApp, nginxSites []model.NginxSite, pools []model.PHPFPMPool) []model.Finding {
	findings := []model.Finding{}
	poolNamesByTarget := map[string]string{}

	for _, pool := range pools {
		normalizedTarget := normalizeFastCGITarget(pool.Listen)
		if normalizedTarget == "" {
			continue
		}

		poolNamesByTarget[normalizedTarget] = pool.Name
	}

	appsByTarget := map[string][]string{}
	for _, app := range apps {
		for _, target := range fastCGITargetsForApp(app, nginxSites) {
			appsByTarget[target] = append(appsByTarget[target], app.RootPath)
		}
	}

	for target, appRoots := range appsByTarget {
		if len(appRoots) < 2 {
			continue
		}

		slices.Sort(appRoots)
		appRoots = slices.Compact(appRoots)
		if len(appRoots) < 2 {
			continue
		}

		poolName := poolNamesByTarget[target]
		evidence := []model.Evidence{
			{Label: "fastcgi_pass", Detail: target},
		}
		for _, appRoot := range appRoots {
			evidence = append(evidence, model.Evidence{Label: "app", Detail: appRoot})
		}
		if poolName != "" {
			evidence = append(evidence, model.Evidence{Label: "pool", Detail: poolName})
		}

		findings = append(findings, model.Finding{
			ID:          buildFindingID(phpFPMSecurityCheckID, "shared_pool", target),
			CheckID:     phpFPMSecurityCheckID,
			Class:       model.FindingClassDirect,
			Severity:    model.SeverityHigh,
			Confidence:  model.ConfidenceConfirmed,
			Title:       "Multiple Laravel apps share the same PHP-FPM socket or port",
			Why:         "When multiple apps use the same PHP-FPM entry point, one compromised app is in a better position to affect the others.",
			Remediation: "Give each Laravel app its own PHP-FPM pool and its own socket or port so app boundaries stay clear.",
			Evidence:    evidence,
			Affected: []model.Target{
				{Type: "value", Value: target},
			},
		})
	}

	return findings
}

func buildSharedRuntimeUserFindings(apps []model.LaravelApp, nginxSites []model.NginxSite, pools []model.PHPFPMPool) []model.Finding {
	findings := []model.Finding{}
	appsByRuntimeUser := map[string][]string{}
	poolsByRuntimeUser := map[string][]string{}

	for _, app := range apps {
		for _, pool := range matchedPHPFPMPoolsForApp(app, nginxSites, pools) {
			runtimeUser := strings.TrimSpace(pool.User)
			if runtimeUser == "" {
				continue
			}

			appsByRuntimeUser[runtimeUser] = append(appsByRuntimeUser[runtimeUser], app.RootPath)
			poolsByRuntimeUser[runtimeUser] = append(poolsByRuntimeUser[runtimeUser], pool.Name)
		}
	}

	for runtimeUser, appRoots := range appsByRuntimeUser {
		slices.Sort(appRoots)
		appRoots = slices.Compact(appRoots)
		if len(appRoots) < 2 {
			continue
		}

		poolNames := poolsByRuntimeUser[runtimeUser]
		slices.Sort(poolNames)
		poolNames = slices.Compact(poolNames)

		evidence := []model.Evidence{
			{Label: "runtime_user", Detail: runtimeUser},
		}
		for _, appRoot := range appRoots {
			evidence = append(evidence, model.Evidence{Label: "app", Detail: appRoot})
		}
		for _, poolName := range poolNames {
			evidence = append(evidence, model.Evidence{Label: "pool", Detail: poolName})
		}

		findings = append(findings, model.Finding{
			ID:          buildFindingID(phpFPMSecurityCheckID, "shared_runtime_user", runtimeUser),
			CheckID:     phpFPMSecurityCheckID,
			Class:       model.FindingClassDirect,
			Severity:    model.SeverityHigh,
			Confidence:  model.ConfidenceConfirmed,
			Title:       "Multiple Laravel apps run under the same PHP-FPM user",
			Why:         "If unrelated apps share the same runtime user, a compromise in one app is more likely to reach the files or processes of another.",
			Remediation: "Use a dedicated PHP-FPM user per Laravel app, or document and justify any shared runtime account explicitly.",
			Evidence:    evidence,
			Affected: []model.Target{
				{Type: "name", Name: runtimeUser},
			},
		})
	}

	return findings
}

func fastCGITargetsForApp(app model.LaravelApp, nginxSites []model.NginxSite) []string {
	targets := []string{}

	for _, site := range nginxSitesForApp(app, nginxSites) {
		for _, target := range site.FastCGIPassTargets {
			normalizedTarget := normalizeFastCGITarget(target)
			if normalizedTarget == "" {
				continue
			}

			targets = append(targets, normalizedTarget)
		}
	}

	slices.Sort(targets)

	return slices.Compact(targets)
}

func normalizeFastCGITarget(target string) string {
	trimmedTarget := strings.TrimSpace(strings.TrimPrefix(target, "unix:"))
	if trimmedTarget == "" {
		return ""
	}

	if !strings.Contains(trimmedTarget, ":") {
		return filepath.Clean(trimmedTarget)
	}

	return trimmedTarget
}

func poolListensOnBroadTCP(listen string) bool {
	normalizedListen := strings.TrimSpace(strings.ToLower(listen))
	if normalizedListen == "" || !strings.Contains(normalizedListen, ":") {
		return false
	}

	for _, loopbackPrefix := range []string{"127.0.0.1:", "localhost:", "[::1]:"} {
		if strings.HasPrefix(normalizedListen, loopbackPrefix) {
			return false
		}
	}

	return true
}

func poolListensOnLoopbackTCP(listen string) bool {
	normalizedListen := strings.TrimSpace(strings.ToLower(listen))
	if normalizedListen == "" || !strings.Contains(normalizedListen, ":") {
		return false
	}

	for _, loopbackPrefix := range []string{"127.0.0.1:", "localhost:", "[::1]:"} {
		if strings.HasPrefix(normalizedListen, loopbackPrefix) {
			return true
		}
	}

	return false
}

func poolUsesUnixSocket(listen string) bool {
	trimmedListen := strings.TrimSpace(listen)
	return trimmedListen != "" && !strings.Contains(trimmedListen, ":")
}

func socketModeExceedsBoundary(mode uint32) bool {
	return mode&^0o660 != 0
}

func socketACLMatchesRuntimeIdentity(pool model.PHPFPMPool) bool {
	return strings.EqualFold(strings.TrimSpace(pool.ListenOwner), strings.TrimSpace(pool.User)) &&
		strings.EqualFold(strings.TrimSpace(pool.ListenGroup), strings.TrimSpace(pool.Group))
}
