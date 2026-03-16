package phpconfig

import (
	"fmt"
	"slices"
	"strings"

	"github.com/nagi1/larainspect/internal/model"
	ini "gopkg.in/ini.v1"
)

func ParsePools(configPath string, contents string) ([]model.PHPFPMPool, error) {
	config, err := ini.LoadSources(ini.LoadOptions{
		IgnoreInlineComment:       false,
		SpaceBeforeInlineComment:  true,
		SkipUnrecognizableLines:   true,
		UnescapeValueDoubleQuotes: true,
		KeyValueDelimiters:        "=",
	}, []byte(contents))
	if err != nil {
		return nil, fmt.Errorf("parse php-fpm config %s: %w", configPath, err)
	}

	sections := config.Sections()
	pools := make([]model.PHPFPMPool, 0, len(sections))
	for _, section := range sections {
		poolName := strings.TrimSpace(section.Name())
		if poolName == "" {
			return nil, fmt.Errorf("php-fpm pool section in %s is missing a name", configPath)
		}
		if poolName == ini.DefaultSection || strings.EqualFold(poolName, "global") {
			continue
		}

		pool := model.PHPFPMPool{
			ConfigPath: configPath,
			Name:       poolName,
		}
		for _, key := range section.Keys() {
			applyPoolDirective(&pool, key.Name(), key.String())
		}
		normalizePool(&pool)
		pools = append(pools, pool)
	}

	return pools, nil
}

func applyPoolDirective(pool *model.PHPFPMPool, directiveName string, directiveValue string) {
	value := cleanValue(directiveValue)
	key := strings.ToLower(strings.TrimSpace(directiveName))

	switch key {
	case "user":
		pool.User = value
	case "group":
		pool.Group = value
	case "listen":
		pool.Listen = value
	case "listen.owner":
		pool.ListenOwner = value
	case "listen.group":
		pool.ListenGroup = value
	case "listen.mode":
		pool.ListenMode = value
	case "clear_env":
		pool.ClearEnv = value
	case "security.limit_extensions":
		pool.SecurityLimitExtensions = append(pool.SecurityLimitExtensions, parseLimitExtensions(value)...)
	default:
		if directiveTargetsPHPValue(key, "cgi.fix_pathinfo") {
			pool.CGIFixPathinfo = value
		}
	}
}

func normalizePool(pool *model.PHPFPMPool) {
	if len(pool.SecurityLimitExtensions) == 0 {
		return
	}

	slices.Sort(pool.SecurityLimitExtensions)
	pool.SecurityLimitExtensions = slices.Compact(pool.SecurityLimitExtensions)
}

func parseLimitExtensions(raw string) []string {
	normalized := strings.NewReplacer(",", " ", "\n", " ", "\t", " ").Replace(cleanValue(raw))
	fields := strings.Fields(normalized)
	if len(fields) == 0 {
		return nil
	}

	extensions := make([]string, 0, len(fields))
	for _, field := range fields {
		cleaned := strings.ToLower(strings.TrimSpace(field))
		if cleaned == "" {
			continue
		}
		if !strings.HasPrefix(cleaned, ".") && cleaned != "*" {
			cleaned = "." + cleaned
		}
		extensions = append(extensions, cleaned)
	}

	return extensions
}

func directiveTargetsPHPValue(directiveName string, valueName string) bool {
	for _, prefix := range []string{"php_admin_value[", "php_value["} {
		if !strings.HasPrefix(directiveName, prefix) || !strings.HasSuffix(directiveName, "]") {
			continue
		}
		innerName := strings.TrimSuffix(strings.TrimPrefix(directiveName, prefix), "]")
		return strings.EqualFold(strings.TrimSpace(innerName), valueName)
	}

	return false
}

func cleanValue(raw string) string {
	value := strings.TrimSpace(raw)
	if len(value) >= 2 {
		if (value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'') {
			return value[1 : len(value)-1]
		}
	}
	return value
}
