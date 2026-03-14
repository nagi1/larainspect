package discovery

import (
	"fmt"
	"slices"
	"strings"

	"github.com/nagi1/larainspect/internal/model"
)

func parseNginxSites(configPath string, contents string) ([]model.NginxSite, error) {
	normalizedContents := stripConfigComments(contents, "#")
	serverBlocks, err := extractNamedBlocks(normalizedContents, "server")
	if err != nil {
		return nil, err
	}

	sites := make([]model.NginxSite, 0, len(serverBlocks))
	for _, serverBlock := range serverBlocks {
		site := model.NginxSite{ConfigPath: configPath}

		for _, statement := range topLevelStatements(serverBlock.Body) {
			directiveName, directiveValue := splitDirective(statement)
			switch directiveName {
			case "root":
				site.Root = trimDirectiveValue(directiveValue)
			case "server_name":
				site.ServerNames = append(site.ServerNames, strings.Fields(directiveValue)...)
			case "index":
				site.IndexFiles = append(site.IndexFiles, strings.Fields(directiveValue)...)
			}
		}

		locationBlocks, locationErr := extractNamedBlocks(serverBlock.Body, "location")
		if locationErr != nil {
			return nil, locationErr
		}

		for _, locationBlock := range locationBlocks {
			applyNginxLocationBlock(&site, locationBlock)
		}

		slices.Sort(site.ServerNames)
		slices.Sort(site.IndexFiles)
		slices.Sort(site.FastCGIPassTargets)
		slices.Sort(site.GenericPHPLocations)
		slices.Sort(site.FrontControllerPaths)
		slices.Sort(site.HiddenDenyMatchers)
		slices.Sort(site.SensitiveDenyMatchers)
		slices.Sort(site.UploadExecutionMatchers)
		site.ServerNames = slices.Compact(site.ServerNames)
		site.IndexFiles = slices.Compact(site.IndexFiles)
		site.FastCGIPassTargets = slices.Compact(site.FastCGIPassTargets)
		site.GenericPHPLocations = slices.Compact(site.GenericPHPLocations)
		site.FrontControllerPaths = slices.Compact(site.FrontControllerPaths)
		site.HiddenDenyMatchers = slices.Compact(site.HiddenDenyMatchers)
		site.SensitiveDenyMatchers = slices.Compact(site.SensitiveDenyMatchers)
		site.UploadExecutionMatchers = slices.Compact(site.UploadExecutionMatchers)
		if site.Root == "" &&
			len(site.ServerNames) == 0 &&
			len(site.IndexFiles) == 0 &&
			len(site.FastCGIPassTargets) == 0 &&
			len(site.GenericPHPLocations) == 0 &&
			len(site.FrontControllerPaths) == 0 &&
			len(site.HiddenDenyMatchers) == 0 &&
			len(site.SensitiveDenyMatchers) == 0 &&
			len(site.UploadExecutionMatchers) == 0 {
			continue
		}
		sites = append(sites, site)
	}

	return sites, nil
}

func applyNginxLocationBlock(site *model.NginxSite, locationBlock configBlock) {
	locationMatcher := strings.TrimSpace(strings.TrimPrefix(locationBlock.Header, "location"))
	locationMatcher = strings.Join(strings.Fields(locationMatcher), " ")
	locationAllowsPHPExecution := matcherAllowsGenericPHPExecution(locationMatcher)
	locationTargetsUploads := matcherTargetsUploadLikePath(locationMatcher)

	if matcherTargetsHiddenFiles(locationMatcher) && locationBlockDeniesAccess(locationBlock.Body) {
		site.HiddenFilesDenied = true
		site.HiddenDenyMatchers = append(site.HiddenDenyMatchers, locationMatcher)
	}

	if matcherTargetsSensitiveFiles(locationMatcher) && locationBlockDeniesAccess(locationBlock.Body) {
		site.SensitiveFilesDenied = true
		site.SensitiveDenyMatchers = append(site.SensitiveDenyMatchers, locationMatcher)
	}

	if locationAllowsPHPExecution {
		site.HasGenericPHPLocation = true
		site.GenericPHPLocations = append(site.GenericPHPLocations, locationMatcher)
	}

	if matcherTargetsFrontControllerOnly(locationMatcher) {
		site.HasFrontControllerOnly = true
		site.FrontControllerPaths = append(site.FrontControllerPaths, locationMatcher)
	}

	if locationAllowsPHPExecution && locationTargetsUploads {
		site.UploadExecutionAllowed = true
		site.UploadExecutionMatchers = append(site.UploadExecutionMatchers, locationMatcher)
	}

	for _, statement := range topLevelStatements(locationBlock.Body) {
		directiveName, directiveValue := splitDirective(statement)
		if directiveName != "fastcgi_pass" {
			continue
		}

		target := trimDirectiveValue(directiveValue)
		if target == "" {
			continue
		}

		site.FastCGIPassTargets = append(site.FastCGIPassTargets, target)
	}
}

type configBlock struct {
	Header string
	Body   string
}

func extractNamedBlocks(contents string, keyword string) ([]configBlock, error) {
	blocks := []configBlock{}
	searchIndex := 0

	for searchIndex < len(contents) {
		keywordIndex := strings.Index(contents[searchIndex:], keyword)
		if keywordIndex < 0 {
			break
		}

		blockStart := searchIndex + keywordIndex
		if !matchesDirectiveBoundary(contents, blockStart, len(keyword)) {
			searchIndex = blockStart + len(keyword)
			continue
		}

		headerEnd := strings.Index(contents[blockStart:], "{")
		if headerEnd < 0 {
			return nil, fmt.Errorf("missing opening brace for %s block", keyword)
		}

		openBraceIndex := blockStart + headerEnd
		header := strings.TrimSpace(contents[blockStart:openBraceIndex])
		closeBraceIndex, err := findMatchingBrace(contents, openBraceIndex)
		if err != nil {
			return nil, err
		}

		blocks = append(blocks, configBlock{
			Header: header,
			Body:   contents[openBraceIndex+1 : closeBraceIndex],
		})
		searchIndex = closeBraceIndex + 1
	}

	return blocks, nil
}

func matchesDirectiveBoundary(contents string, startIndex int, keywordLength int) bool {
	if startIndex > 0 {
		if previousCharacter := contents[startIndex-1]; isIdentifierCharacter(previousCharacter) {
			return false
		}
	}

	endIndex := startIndex + keywordLength
	if endIndex < len(contents) {
		if nextCharacter := contents[endIndex]; isIdentifierCharacter(nextCharacter) {
			return false
		}
	}

	return true
}

func findMatchingBrace(contents string, openBraceIndex int) (int, error) {
	depth := 0

	for index := openBraceIndex; index < len(contents); index++ {
		switch contents[index] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return index, nil
			}
		}
	}

	return -1, fmt.Errorf("missing closing brace")
}

func isIdentifierCharacter(character byte) bool {
	return character == '_' || character == '-' || (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9')
}

func topLevelStatements(contents string) []string {
	statements := []string{}
	var builder strings.Builder
	depth := 0

	for index := 0; index < len(contents); index++ {
		switch contents[index] {
		case '{':
			depth++
			if depth == 1 {
				builder.Reset()
			}
		case '}':
			if depth > 0 {
				depth--
			}
		case ';':
			if depth == 0 {
				statement := strings.TrimSpace(builder.String())
				if statement != "" {
					statements = append(statements, statement)
				}
				builder.Reset()
			}
		default:
			if depth == 0 {
				builder.WriteByte(contents[index])
			}
		}
	}

	return statements
}

func splitDirective(statement string) (string, string) {
	fields := strings.Fields(statement)
	if len(fields) == 0 {
		return "", ""
	}

	directiveName := fields[0]
	directiveValue := strings.TrimSpace(strings.TrimPrefix(statement, directiveName))

	return directiveName, directiveValue
}

func trimDirectiveValue(value string) string {
	return strings.Trim(strings.TrimSpace(value), "\"'")
}

func stripConfigComments(contents string, commentPrefix string) string {
	lines := strings.Split(contents, "\n")
	for index, line := range lines {
		if commentIndex := strings.Index(line, commentPrefix); commentIndex >= 0 {
			lines[index] = line[:commentIndex]
		}
	}

	return strings.Join(lines, "\n")
}

func matcherAllowsGenericPHPExecution(matcher string) bool {
	normalizedMatcher := strings.ToLower(strings.TrimSpace(matcher))
	if normalizedMatcher == "" {
		return false
	}

	if matcherTargetsFrontControllerOnly(normalizedMatcher) {
		return false
	}

	return containsExecutablePHPMatcher(normalizedMatcher)
}

func containsExecutablePHPMatcher(matcher string) bool {
	for _, token := range []string{
		".php", "php$", "php|", "php)",
		".phtml", "phtml$", "phtml|", "phtml)",
		".pht", "pht$", "pht|", "pht)",
		".phar", "phar$", "phar|", "phar)",
		".php3", "php3$", "php3|", "php3)",
		".php4", "php4$", "php4|", "php4)",
		".php5", "php5$", "php5|", "php5)",
		".php7", "php7$", "php7|", "php7)",
		".php8", "php8$", "php8|", "php8)",
	} {
		if strings.Contains(matcher, token) {
			return true
		}
	}

	return false
}

func matcherTargetsFrontControllerOnly(matcher string) bool {
	normalizedMatcher := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(matcher), " ", ""))
	return normalizedMatcher == "=/index.php" || normalizedMatcher == "/index.php"
}

func matcherTargetsHiddenFiles(matcher string) bool {
	normalizedMatcher := strings.ToLower(strings.TrimSpace(matcher))
	return strings.Contains(normalizedMatcher, `\.`) || strings.Contains(normalizedMatcher, "/.")
}

func matcherTargetsSensitiveFiles(matcher string) bool {
	normalizedMatcher := strings.ToLower(strings.TrimSpace(matcher))
	for _, token := range []string{".env", ".git", ".svn", ".sql", ".zip", ".tar", ".gz", ".log", "env", "git", "svn", "sql", "zip", "tar", "gz", "log"} {
		if strings.Contains(normalizedMatcher, token) {
			return true
		}
	}

	return false
}

func matcherTargetsUploadLikePath(matcher string) bool {
	normalizedMatcher := strings.ToLower(strings.TrimSpace(matcher))
	for _, token := range []string{"upload", "uploads", "storage", "media", "files"} {
		if strings.Contains(normalizedMatcher, token) {
			return true
		}
	}

	return false
}

func locationBlockDeniesAccess(blockBody string) bool {
	for _, statement := range topLevelStatements(blockBody) {
		directiveName, directiveValue := splitDirective(statement)
		normalizedValue := strings.ToLower(strings.TrimSpace(directiveValue))

		switch directiveName {
		case "deny":
			if normalizedValue == "all" {
				return true
			}
		case "return":
			if normalizedValue == "403" || normalizedValue == "404" {
				return true
			}
		}
	}

	return false
}
