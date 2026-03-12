package checks

import (
	"context"
	"path/filepath"
	"slices"
	"strings"

	"github.com/nagi1/larainspect/internal/model"
)

const phpFPMSecurityCheckID = "phpfpm.security"

type PHPFPMSecurityCheck struct{}

func init() {
	MustRegister(PHPFPMSecurityCheck{})
}

func (PHPFPMSecurityCheck) ID() string {
	return phpFPMSecurityCheckID
}

func (PHPFPMSecurityCheck) Run(_ context.Context, _ model.ExecutionContext, snapshot model.Snapshot) (model.CheckResult, error) {
	findings := []model.Finding{}

	for _, pool := range snapshot.PHPFPMPools {
		if rootPoolFinding, found := buildRootPoolFinding(pool); found {
			findings = append(findings, rootPoolFinding)
		}

		if exposedTCPFinding, found := buildExposedTCPPoolFinding(pool); found {
			findings = append(findings, exposedTCPFinding)
		}

		if socketModeFinding, found := buildBroadSocketModeFinding(pool); found {
			findings = append(findings, socketModeFinding)
		}
	}

	for _, sharedPoolFinding := range buildSharedPoolFindings(snapshot.Apps, snapshot.NginxSites, snapshot.PHPFPMPools) {
		findings = append(findings, sharedPoolFinding)
	}

	return model.CheckResult{Findings: findings}, nil
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
		Title:       "PHP-FPM pool runs as root",
		Why:         "A root PHP-FPM worker turns application compromise into host-level compromise much more easily.",
		Remediation: "Run each PHP-FPM pool as a dedicated non-root runtime user with the minimum filesystem permissions required by the Laravel app.",
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
		Title:       "PHP-FPM pool listens on a broad TCP address",
		Why:         "Broad TCP exposure makes PHP-FPM reachable outside the intended local trust boundary and increases remote attack surface.",
		Remediation: "Prefer a Unix socket for local Nginx integration, or restrict TCP listeners to loopback or an explicitly trusted internal address only.",
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
	if strings.Contains(pool.Listen, ":") || strings.TrimSpace(pool.ListenMode) == "" {
		return model.Finding{}, false
	}

	listenMode, ok := parseOctalMode(pool.ListenMode)
	if !ok || listenMode&0o002 == 0 {
		return model.Finding{}, false
	}

	return model.Finding{
		ID:          buildFindingID(phpFPMSecurityCheckID, "broad_socket_mode", pool.ConfigPath+"."+pool.Name),
		CheckID:     phpFPMSecurityCheckID,
		Class:       model.FindingClassDirect,
		Severity:    model.SeverityHigh,
		Confidence:  model.ConfidenceConfirmed,
		Title:       "PHP-FPM socket permissions are too broad",
		Why:         "A world-writable PHP-FPM socket lets unintended local users connect to the pool and execute PHP requests.",
		Remediation: "Restrict the pool socket to the intended Nginx owner and group, usually with mode 0660, and avoid world-writable socket permissions.",
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
			Title:       "Multiple Laravel apps share the same PHP-FPM pool target",
			Why:         "Shared PHP-FPM pools weaken app isolation and make lateral movement easier when one Laravel app is compromised.",
			Remediation: "Use a dedicated PHP-FPM pool and socket or listener per Laravel app so runtime identity and request isolation stay explicit.",
			Evidence:    evidence,
			Affected: []model.Target{
				{Type: "value", Value: target},
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
