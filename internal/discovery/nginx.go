package discovery

import (
	"bytes"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"

	crossplane "github.com/nginxinc/nginx-go-crossplane"

	"github.com/nagi1/larainspect/internal/model"
)

// parseNginxSites parses a single nginx config file's content and returns NginxSite records.
func parseNginxSites(configPath string, contents string) ([]model.NginxSite, error) {
	directives, err := parseNginxContent(configPath, contents)
	if err != nil {
		return nil, err
	}

	return extractNginxSites(configPath, directives), nil
}

// parseNginxSitesResolving parses an nginx config file with include resolution.
// Included files are opened via readFile; glob patterns via globPaths.
func parseNginxSitesResolving(configPath string, contents []byte, readFile func(string) ([]byte, error), globPaths func(string) ([]string, error)) ([]model.NginxSite, error) {
	payload, err := crossplane.Parse(configPath, &crossplane.ParseOptions{
		Open: func(path string) (io.ReadCloser, error) {
			if path == configPath {
				return io.NopCloser(bytes.NewReader(contents)), nil
			}
			data, readErr := readFile(path)
			if readErr != nil {
				return nil, readErr
			}
			return io.NopCloser(bytes.NewReader(data)), nil
		},
		Glob: func(pattern string) ([]string, error) {
			return globPaths(pattern)
		},
		SkipDirectiveContextCheck: true,
		SkipDirectiveArgsCheck:    true,
	})
	if err != nil {
		return nil, fmt.Errorf("parse nginx config: %w", err)
	}

	if parseErr := firstNginxPayloadError(payload); parseErr != nil {
		return nil, parseErr
	}

	// Combine included configs into one so include directives are inlined.
	combined, combineErr := payload.Combined()
	if combineErr != nil {
		return nil, fmt.Errorf("combine nginx configs: %w", combineErr)
	}

	var sites []model.NginxSite
	for _, config := range combined.Config {
		filePath := config.File
		if filePath == "" {
			filePath = configPath
		}
		sites = append(sites, extractNginxSites(filePath, config.Parsed)...)
	}
	return sites, nil
}

// parseNginxDump parses the concatenated output of `nginx -T` which contains
// multiple configuration file sections separated by "# configuration file" markers.
func parseNginxDump(combinedOutput string) ([]model.NginxSite, error) {
	sections := splitNginxDumpSections(combinedOutput)

	var allSites []model.NginxSite
	for _, section := range sections {
		sites, err := parseNginxSites(section.path, section.contents)
		if err != nil {
			return nil, fmt.Errorf("parse nginx config %s: %w", section.path, err)
		}
		allSites = append(allSites, sites...)
	}

	return allSites, nil
}

type nginxConfigSection struct {
	path     string
	contents string
}

var nginxTSectionHeader = regexp.MustCompile(`(?m)^# configuration file (.+):$`)

// splitNginxDumpSections splits nginx -T output into per-file sections.
// Lines before the first "# configuration file" marker (e.g. nginx status lines) are discarded.
func splitNginxDumpSections(dump string) []nginxConfigSection {
	matches := nginxTSectionHeader.FindAllStringSubmatchIndex(dump, -1)
	if len(matches) == 0 {
		content := strings.TrimSpace(dump)
		if content == "" {
			return nil
		}
		return []nginxConfigSection{{path: "nginx", contents: content}}
	}

	sections := make([]nginxConfigSection, 0, len(matches))
	for i, match := range matches {
		path := dump[match[2]:match[3]]
		contentStart := match[1]
		contentEnd := len(dump)
		if i+1 < len(matches) {
			contentEnd = matches[i+1][0]
		}
		content := strings.TrimSpace(dump[contentStart:contentEnd])
		if content != "" {
			sections = append(sections, nginxConfigSection{path: path, contents: content})
		}
	}
	return sections
}

// parseNginxContent uses crossplane to lex and parse raw nginx config text into a directive tree.
func parseNginxContent(configPath string, contents string) (crossplane.Directives, error) {
	payload, err := crossplane.Parse(configPath, &crossplane.ParseOptions{
		SingleFile:                true,
		StopParsingOnError:        true,
		SkipDirectiveContextCheck: true,
		SkipDirectiveArgsCheck:    true,
		Open: func(_ string) (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader(contents)), nil
		},
	})
	if err != nil {
		return nil, fmt.Errorf("parse nginx config: %w", err)
	}
	if parseErr := firstNginxPayloadError(payload); parseErr != nil {
		return nil, parseErr
	}

	if len(payload.Config) == 0 {
		return nil, nil
	}
	return payload.Config[0].Parsed, nil
}

func firstNginxPayloadError(payload *crossplane.Payload) error {
	if payload == nil {
		return nil
	}
	if len(payload.Errors) > 0 {
		first := payload.Errors[0]
		if first.File != "" {
			return fmt.Errorf("parse nginx config %s: %w", first.File, first.Error)
		}
		return fmt.Errorf("parse nginx config: %w", first.Error)
	}
	for _, config := range payload.Config {
		if len(config.Errors) == 0 {
			continue
		}
		if config.File != "" {
			return fmt.Errorf("parse nginx config %s: %w", config.File, config.Errors[0].Error)
		}
		return fmt.Errorf("parse nginx config: %w", config.Errors[0].Error)
	}
	return nil
}

// extractNginxSites walks a crossplane directive tree and returns NginxSite records
// for every server block found (including those nested inside http blocks).
func extractNginxSites(configPath string, directives crossplane.Directives) []model.NginxSite {
	var sites []model.NginxSite
	for _, d := range directives {
		switch d.Directive {
		case "server":
			if d.IsBlock() {
				site := buildNginxSiteFromServer(configPath, d)
				if !isEmptyNginxSite(site) {
					sites = append(sites, site)
				}
			}
		case "http":
			if d.IsBlock() {
				sites = append(sites, extractNginxSites(configPath, d.Block)...)
			}
		}
	}
	return sites
}

func buildNginxSiteFromServer(configPath string, serverDir *crossplane.Directive) model.NginxSite {
	site := model.NginxSite{ConfigPath: configPath}

	for _, d := range serverDir.Block {
		switch d.Directive {
		case "root":
			if len(d.Args) > 0 {
				site.Root = d.Args[0]
			}
		case "server_name":
			site.ServerNames = append(site.ServerNames, d.Args...)
		case "index":
			site.IndexFiles = append(site.IndexFiles, d.Args...)
		case "location":
			if d.IsBlock() {
				applyNginxLocationDirective(&site, d)
			}
		}
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

	return site
}

func isEmptyNginxSite(site model.NginxSite) bool {
	return site.Root == "" &&
		len(site.ServerNames) == 0 &&
		len(site.IndexFiles) == 0 &&
		len(site.FastCGIPassTargets) == 0 &&
		len(site.GenericPHPLocations) == 0 &&
		len(site.FrontControllerPaths) == 0 &&
		len(site.HiddenDenyMatchers) == 0 &&
		len(site.SensitiveDenyMatchers) == 0 &&
		len(site.UploadExecutionMatchers) == 0
}

func applyNginxLocationDirective(site *model.NginxSite, locationDir *crossplane.Directive) {
	locationMatcher := strings.Join(locationDir.Args, " ")
	fastCGITargets := extractFastCGIPassTargets(locationDir.Block)
	locationAllowsPHPExecution := matcherAllowsGenericPHPExecution(locationMatcher) && len(fastCGITargets) > 0
	locationTargetsUploads := matcherTargetsUploadLikePath(locationMatcher)

	if matcherTargetsHiddenFiles(locationMatcher) && directiveBlockDeniesAccess(locationDir.Block) {
		site.HiddenFilesDenied = true
		site.HiddenDenyMatchers = append(site.HiddenDenyMatchers, locationMatcher)
	}

	if matcherTargetsSensitiveFiles(locationMatcher) && directiveBlockDeniesAccess(locationDir.Block) {
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

	site.FastCGIPassTargets = append(site.FastCGIPassTargets, fastCGITargets...)
}

// extractFastCGIPassTargets returns all fastcgi_pass target values from a directive block.
func extractFastCGIPassTargets(directives crossplane.Directives) []string {
	var targets []string
	for _, d := range directives {
		if d.Directive == "fastcgi_pass" && len(d.Args) > 0 {
			targets = append(targets, d.Args[0])
		}
	}
	return targets
}

// directiveBlockDeniesAccess returns true if the block contains deny all or return 403/404.
func directiveBlockDeniesAccess(directives crossplane.Directives) bool {
	for _, d := range directives {
		switch d.Directive {
		case "deny":
			if len(d.Args) > 0 && strings.EqualFold(d.Args[0], "all") {
				return true
			}
		case "return":
			if len(d.Args) > 0 && (d.Args[0] == "403" || d.Args[0] == "404") {
				return true
			}
		}
	}
	return false
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
