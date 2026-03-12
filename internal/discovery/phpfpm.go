package discovery

import (
	"fmt"
	"strings"

	"github.com/nagi1/larainspect/internal/model"
)

func parsePHPFPMPools(configPath string, contents string) ([]model.PHPFPMPool, error) {
	normalizedContents := stripPHPFPMComments(contents)
	pools := []model.PHPFPMPool{}
	var currentPool *model.PHPFPMPool

	for _, rawLine := range strings.Split(normalizedContents, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			if currentPool != nil {
				pools = append(pools, *currentPool)
			}

			poolName := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "["), "]"))
			if poolName == "" {
				return nil, fmt.Errorf("php-fpm pool section in %s is missing a name", configPath)
			}

			currentPool = &model.PHPFPMPool{
				ConfigPath: configPath,
				Name:       poolName,
			}
			continue
		}

		if currentPool == nil {
			continue
		}

		key, value, foundSeparator := strings.Cut(line, "=")
		if !foundSeparator {
			continue
		}

		applyPHPFPMDirective(currentPool, strings.TrimSpace(key), strings.TrimSpace(value))
	}

	if currentPool != nil {
		pools = append(pools, *currentPool)
	}

	return pools, nil
}

func stripPHPFPMComments(contents string) string {
	lines := strings.Split(contents, "\n")
	for index, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		if strings.HasPrefix(trimmedLine, ";") || strings.HasPrefix(trimmedLine, "#") {
			lines[index] = ""
		}
	}

	return strings.Join(lines, "\n")
}

func applyPHPFPMDirective(pool *model.PHPFPMPool, directiveName string, directiveValue string) {
	switch directiveName {
	case "user":
		pool.User = directiveValue
	case "group":
		pool.Group = directiveValue
	case "listen":
		pool.Listen = directiveValue
	case "listen.owner":
		pool.ListenOwner = directiveValue
	case "listen.group":
		pool.ListenGroup = directiveValue
	case "listen.mode":
		pool.ListenMode = directiveValue
	case "clear_env":
		pool.ClearEnv = directiveValue
	}
}
