package checks

import (
	"path/filepath"
	"slices"
	"strings"

	"github.com/nagi1/larainspect/internal/model"
)

func buildContextualPHPRuntimeFindings(app model.LaravelApp, snapshot model.Snapshot) []model.Finding {
	matchedSites := nginxSitesForApp(app, snapshot.NginxSites)
	if !anySiteAllowsGenericPHPExecution(matchedSites) {
		return nil
	}

	matchedPools := matchedPHPFPMPoolsForApp(app, snapshot.NginxSites, snapshot.PHPFPMPools)
	findings := []model.Finding{}

	if finding, found := buildBroadLimitExtensionsFinding(app, matchedSites, matchedPools); found {
		findings = append(findings, finding)
	}
	if finding, found := buildCGIFixPathinfoFinding(app, matchedSites, matchedPools, snapshot.PHPINIConfigs); found {
		findings = append(findings, finding)
	}

	return findings
}

func buildBroadLimitExtensionsFinding(app model.LaravelApp, matchedSites []model.NginxSite, matchedPools []model.PHPFPMPool) (model.Finding, bool) {
	broadExtensions := []string{}
	poolConfigs := []string{}
	for _, pool := range matchedPools {
		additionalExtensions := securityExtensionsBeyondPHP(pool.SecurityLimitExtensions)
		if len(additionalExtensions) == 0 {
			continue
		}
		broadExtensions = append(broadExtensions, additionalExtensions...)
		poolConfigs = append(poolConfigs, pool.ConfigPath)
	}
	if len(broadExtensions) == 0 {
		return model.Finding{}, false
	}

	slices.Sort(broadExtensions)
	broadExtensions = slices.Compact(broadExtensions)
	slices.Sort(poolConfigs)
	poolConfigs = slices.Compact(poolConfigs)

	evidence := []model.Evidence{{Label: "app", Detail: app.RootPath}}
	for _, site := range matchedSites {
		evidence = append(evidence, model.Evidence{Label: "nginx_config", Detail: site.ConfigPath})
	}
	for _, configPath := range poolConfigs {
		evidence = append(evidence, model.Evidence{Label: "php_fpm_config", Detail: configPath})
	}
	evidence = append(evidence, model.Evidence{Label: "security.limit_extensions", Detail: strings.Join(broadExtensions, ", ")})

	return model.Finding{
		ID:          buildFindingID(phpFPMSecurityCheckID, "broad_limit_extensions", app.RootPath),
		CheckID:     phpFPMSecurityCheckID,
		Class:       model.FindingClassDirect,
		Severity:    model.SeverityHigh,
		Confidence:  model.ConfidenceConfirmed,
		Title:       "Nginx and PHP-FPM together allow extra executable PHP extensions",
		Why:         "Nginx already forwards generic PHP requests, and this PHP-FPM pool explicitly allows extensions beyond .php, which increases the chance that stray files or uploads execute as code.",
		Remediation: "Keep Nginx on front-controller-only PHP routing where possible and restrict security.limit_extensions to the smallest set required, usually .php only.",
		Evidence:    evidence,
		Affected: []model.Target{
			appTarget(app),
		},
	}, true
}

func buildCGIFixPathinfoFinding(app model.LaravelApp, matchedSites []model.NginxSite, matchedPools []model.PHPFPMPool, phpINIConfigs []model.PHPINIConfig) (model.Finding, bool) {
	value, sourcePath, sourceLabel := effectiveCGIFixPathinfo(matchedPools, phpINIConfigs)
	if !phpRuntimeBooleanEnabled(value) {
		return model.Finding{}, false
	}

	evidence := []model.Evidence{{Label: "app", Detail: app.RootPath}}
	for _, site := range matchedSites {
		evidence = append(evidence, model.Evidence{Label: "nginx_config", Detail: site.ConfigPath})
	}
	evidence = append(evidence, model.Evidence{Label: sourceLabel, Detail: sourcePath})
	evidence = append(evidence, model.Evidence{Label: "cgi.fix_pathinfo", Detail: value})

	return model.Finding{
		ID:          buildFindingID(phpFPMSecurityCheckID, "cgi_fix_pathinfo_enabled", app.RootPath),
		CheckID:     phpFPMSecurityCheckID,
		Class:       model.FindingClassDirect,
		Severity:    model.SeverityHigh,
		Confidence:  model.ConfidenceConfirmed,
		Title:       "Generic PHP execution is paired with cgi.fix_pathinfo=1",
		Why:         "When Nginx forwards generic PHP requests and cgi.fix_pathinfo remains enabled, path-info based requests are harder to reason about and are more likely to reach unintended scripts.",
		Remediation: "Prefer front-controller-only PHP routing in Nginx and keep cgi.fix_pathinfo disabled for PHP-FPM unless a specific legacy workload requires it.",
		Evidence:    evidence,
		Affected: []model.Target{
			appTarget(app),
		},
	}, true
}
func securityExtensionsBeyondPHP(extensions []string) []string {
	if len(extensions) == 0 {
		return nil
	}

	additional := []string{}
	for _, extension := range extensions {
		normalized := strings.ToLower(strings.TrimSpace(extension))
		if normalized == "" || normalized == ".php" {
			continue
		}
		additional = append(additional, normalized)
	}
	return additional
}

func effectiveCGIFixPathinfo(matchedPools []model.PHPFPMPool, phpINIConfigs []model.PHPINIConfig) (string, string, string) {
	for _, pool := range matchedPools {
		if strings.TrimSpace(pool.CGIFixPathinfo) == "" {
			continue
		}
		return pool.CGIFixPathinfo, pool.ConfigPath, "php_fpm_config"
	}

	for _, pool := range matchedPools {
		matchedConfig, found := matchedPHPINIConfigForPool(pool, phpINIConfigs)
		if !found || strings.TrimSpace(matchedConfig.CGIFixPathinfo) == "" {
			continue
		}
		return matchedConfig.CGIFixPathinfo, matchedConfig.ConfigPath, "php_ini"
	}

	if len(phpINIConfigs) == 1 && strings.TrimSpace(phpINIConfigs[0].CGIFixPathinfo) != "" {
		return phpINIConfigs[0].CGIFixPathinfo, phpINIConfigs[0].ConfigPath, "php_ini"
	}

	return "", "", ""
}

func matchedPHPINIConfigForPool(pool model.PHPFPMPool, configs []model.PHPINIConfig) (model.PHPINIConfig, bool) {
	poolRoot := phpRuntimeRootForPoolConfig(pool.ConfigPath)
	if poolRoot == "" {
		return model.PHPINIConfig{}, false
	}

	for _, config := range configs {
		if phpRuntimeRootForINIConfig(config.ConfigPath) == poolRoot {
			return config, true
		}
	}

	return model.PHPINIConfig{}, false
}

func phpRuntimeRootForPoolConfig(configPath string) string {
	cleanPath := filepath.Clean(strings.TrimSpace(configPath))
	for _, marker := range []string{"/pool.d/", "/php-fpm.d/"} {
		if index := strings.Index(cleanPath, marker); index >= 0 {
			return cleanPath[:index]
		}
	}
	if filepath.Base(cleanPath) == "php-fpm.conf" {
		return filepath.Dir(cleanPath)
	}
	return ""
}

func phpRuntimeRootForINIConfig(configPath string) string {
	cleanPath := filepath.Clean(strings.TrimSpace(configPath))
	if filepath.Base(cleanPath) != "php.ini" {
		return ""
	}
	return filepath.Dir(cleanPath)
}

func phpRuntimeBooleanEnabled(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "on", "yes":
		return true
	default:
		return false
	}
}
