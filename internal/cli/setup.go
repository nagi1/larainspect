package cli

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/nagi1/larainspect/internal/model"
	"github.com/nagi1/larainspect/internal/runner"
	"github.com/nagi1/larainspect/internal/ux"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

const defaultGeneratedConfigPath = "larainspect.yaml"

type configPreset string

const (
	presetVPS          configPreset = "vps"
	presetForge        configPreset = "forge"
	presetDigitalOcean configPreset = "digitalocean"
	presetAAPanel      configPreset = "aapanel"
	presetCPanel       configPreset = "cpanel"
)

type generatedConfigOptions struct {
	path   string
	preset string
}

type presetDetection struct {
	preset configPreset
	reason string
}

type hostInspector struct {
	getwd    func() (string, error)
	hostname func() (string, error)
	stat     func(string) (fs.FileInfo, error)
	glob     func(string) ([]string, error)
	readFile func(string) ([]byte, error)
}

func newHostInspector() hostInspector {
	return hostInspector{
		getwd:    os.Getwd,
		hostname: os.Hostname,
		stat:     os.Stat,
		glob:     filepath.Glob,
		readFile: os.ReadFile,
	}
}

func (app App) newInitCommand() *cobra.Command {
	var options generatedConfigOptions

	cmd := &cobra.Command{
		Use:           "init",
		Short:         "Write a starter larainspect.yaml in the current directory",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if exitCode := runInitCommandWithInspector(cmd.OutOrStdout(), cmd.ErrOrStderr(), options, newHostInspector()); exitCode != 0 {
				return &commandError{code: exitCode}
			}
			return nil
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&options.path, "path", defaultGeneratedConfigPath, "Output path for the generated config")
	flags.StringVar(&options.preset, "preset", "", "Optional preset: forge, digitalocean, aapanel, cpanel, or vps")
	cmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		printInitHelp(cmd.OutOrStdout())
	})
	cmd.SetFlagErrorFunc(func(cmd *cobra.Command, err error) error {
		return newUsageError(err, printInitHelp)
	})

	return cmd
}

func (app App) newSetupCommand() *cobra.Command {
	var options generatedConfigOptions

	cmd := &cobra.Command{
		Use:           "setup",
		Short:         "Detect a hosting preset and generate a tuned larainspect.yaml",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if exitCode := runSetupCommandWithInspector(app.stdin, cmd.OutOrStdout(), cmd.ErrOrStderr(), options, newHostInspector()); exitCode != 0 {
				return &commandError{code: exitCode}
			}
			return nil
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&options.path, "path", defaultGeneratedConfigPath, "Output path for the generated config")
	flags.StringVar(&options.preset, "preset", "", "Skip auto-detection and force a preset")
	cmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		printSetupHelp(cmd.OutOrStdout())
	})
	cmd.SetFlagErrorFunc(func(cmd *cobra.Command, err error) error {
		return newUsageError(err, printSetupHelp)
	})

	return cmd
}

func runInitCommandWithInspector(stdout io.Writer, stderr io.Writer, options generatedConfigOptions, inspector hostInspector) int {
	preset, err := resolveRequestedPreset(options.preset)
	if err != nil {
		return writeGeneratedConfigUsageError(stderr, err, printInitHelp)
	}

	config := buildGeneratedConfig(preset, inspector, generatedAnswers{})
	if err := writeGeneratedConfigFile(resolveGeneratedConfigPath(options.path), config, "init", stdout); err != nil {
		fmt.Fprintln(stderr, err)
		return int(model.ExitCodeUsageError)
	}

	return 0
}

func runSetupCommandWithInspector(stdin io.Reader, stdout io.Writer, stderr io.Writer, options generatedConfigOptions, inspector hostInspector) int {
	answers := generatedAnswers{}
	preset, err := resolveRequestedPreset(options.preset)
	if err != nil {
		return writeGeneratedConfigUsageError(stderr, err, printSetupHelp)
	}

	if preset == "" {
		guess, guessed := detectHostingPreset(inspector)
		if guessed {
			preset = guess.preset
			answers.reason = guess.reason
		} else {
			wizardDefaults := ux.SetupAnswers{
				Preset:   string(presetVPS),
				OSFamily: detectOSFamily(inspector),
				Scope:    defaultGeneratedScope(inspector),
				AppPath:  detectLaravelAppPath(inspector),
			}
			wizardAnswers, promptErr := ux.Prompter{Input: stdin, Output: stderr}.ResolveSetupAnswers(wizardDefaults)
			if promptErr != nil {
				return writeGeneratedConfigUsageError(stderr, promptErr, printSetupHelp)
			}

			preset, err = resolveRequestedPreset(wizardAnswers.Preset)
			if err != nil {
				return writeGeneratedConfigUsageError(stderr, err, printSetupHelp)
			}
			answers.osFamily = strings.TrimSpace(wizardAnswers.OSFamily)
			answers.scope = wizardAnswers.Scope
			answers.appPath = strings.TrimSpace(wizardAnswers.AppPath)
			answers.reason = "selected via guided setup"
		}
	}

	config := buildGeneratedConfig(preset, inspector, answers)
	if err := writeGeneratedConfigFile(resolveGeneratedConfigPath(options.path), config, "setup", stdout); err != nil {
		fmt.Fprintln(stderr, err)
		return int(model.ExitCodeUsageError)
	}

	return 0
}

type generatedAnswers struct {
	osFamily string
	scope    model.ScanScope
	appPath  string
	reason   string
}

func resolveRequestedPreset(raw string) (configPreset, error) {
	switch normalized := strings.ToLower(strings.TrimSpace(raw)); normalized {
	case "":
		return "", nil
	case "default", "vps", "normal", "normal-vps":
		return presetVPS, nil
	case "forge", "forage":
		return presetForge, nil
	case "digitalocean", "digital-ocean", "do":
		return presetDigitalOcean, nil
	case "aapanel", "aa-panel", "aa_panel":
		return presetAAPanel, nil
	case "cpanel", "c-panel":
		return presetCPanel, nil
	default:
		return "", fmt.Errorf("unsupported preset %q", raw)
	}
}

func detectHostingPreset(inspector hostInspector) (presetDetection, bool) {
	if pathExists(inspector, "/www/server/panel") || pathExists(inspector, "/www/server/nginx/sbin/nginx") {
		return presetDetection{preset: presetAAPanel, reason: "detected aaPanel install paths under /www/server"}, true
	}
	if pathExists(inspector, "/usr/local/cpanel") || pathExists(inspector, "/var/cpanel") || pathExists(inspector, "/var/cpanel/ApachePHPFPM") || globHasMatch(inspector, "/opt/cpanel/ea-php*/root/etc/php-fpm.d/*.conf") || globHasMatch(inspector, "/var/cpanel/userdata/*/*.php_fpm.yaml") {
		return presetDetection{preset: presetCPanel, reason: "detected cPanel directories or EA-PHP-FPM configuration"}, true
	}
	if pathExists(inspector, "/home/forge") {
		return presetDetection{preset: presetForge, reason: "detected the Forge home directory"}, true
	}
	if pathExists(inspector, "/etc/digitalocean") || pathExists(inspector, "/etc/default/do-agent") || pathExists(inspector, "/lib/systemd/system/do-agent.service") || pathExists(inspector, "/var/www/laravel") {
		return presetDetection{preset: presetDigitalOcean, reason: "detected DigitalOcean agent files or the default Laravel droplet root"}, true
	}

	return presetDetection{}, false
}

func buildGeneratedConfig(preset configPreset, inspector hostInspector, answers generatedAnswers) model.AuditConfig {
	config := model.DefaultAuditConfig()
	config.WorkerLimit = runner.DefaultWorkerLimit()
	config.Profile.Name = detectedHostname(inspector)

	osFamily := strings.TrimSpace(answers.osFamily)
	if osFamily == "" {
		osFamily = detectOSFamily(inspector)
	}
	config.Profile.OSFamily = osFamily

	appPath := strings.TrimSpace(answers.appPath)
	if appPath == "" {
		appPath = detectPlatformAppPath(preset, inspector)
	}
	if appPath == "" {
		appPath = detectLaravelAppPath(inspector)
	}

	scope := answers.scope
	if !scope.Valid() {
		scope = defaultGeneratedScope(inspector)
	}
	config.Scope = scope
	config.AppPath = appPath
	if config.Scope == model.ScanScopeApp && config.AppPath == "" {
		config.Scope = model.ScanScopeAuto
	}

	config.Profile.Paths.AppScanRoots = defaultScanRoots(preset)

	switch preset {
	case presetForge:
		config.Profile.Paths.AppScanRoots = []string{"/home/forge"}
	case presetDigitalOcean:
		config.Profile.Paths.AppScanRoots = []string{"/var/www", "/srv/www", "/home"}
	case presetAAPanel:
		config.Profile.Paths.AppScanRoots = []string{"/www/wwwroot"}
		config.Profile.Commands.NginxBinary = "/www/server/nginx/sbin/nginx"
		config.Profile.Commands.SupervisorBinary = "/www/server/panel/pyenv/bin/supervisord"
		config.Profile.Commands.PHPFPMBinaries = globMatches(inspector, "/www/server/php/*/sbin/php-fpm")
	case presetCPanel:
		config.Profile.Paths.AppScanRoots = []string{"/home"}
		config.Profile.Paths.UseDefaultPatterns = false
		config.Profile.Paths.NginxConfigPatterns = cpanelNginxConfigPatterns(inspector)
		config.Profile.Switches.DiscoverNginx = len(config.Profile.Paths.NginxConfigPatterns) != 0
		config.Profile.Switches.DiscoverSupervisor = false
		config.Profile.Paths.SupervisorConfigPatterns = nil
		config.Profile.Paths.PHPFPMPoolPatterns = []string{
			"/opt/cpanel/ea-php*/root/etc/php-fpm.d/*.conf",
			"/opt/cpanel/ea-php*/root/usr/etc/php-fpm.d/*.conf",
		}
		config.Profile.Commands.PHPFPMBinaries = append(globMatches(inspector, "/opt/cpanel/ea-php*/root/usr/sbin/php-fpm"), globMatches(inspector, "/usr/local/bin/ea-php*-php-fpm")...)
	default:
		config.Profile.Paths.AppScanRoots = defaultScanRoots(presetVPS)
	}

	config.Profile.Commands.PHPFPMBinaries = dedupeSorted(config.Profile.Commands.PHPFPMBinaries)

	return config
}

func defaultGeneratedScope(inspector hostInspector) model.ScanScope {
	if detectLaravelAppPath(inspector) != "" {
		return model.ScanScopeApp
	}

	return model.ScanScopeAuto
}

func detectPlatformAppPath(preset configPreset, inspector hostInspector) string {
	for _, candidate := range candidateAppPathsForPreset(preset, inspector) {
		if looksLikeLaravelApp(inspector, candidate) {
			return candidate
		}
	}

	return ""
}

func candidateAppPathsForPreset(preset configPreset, inspector hostInspector) []string {
	switch preset {
	case presetForge:
		return append(
			globMatches(inspector, "/home/forge/*/current"),
			globMatches(inspector, "/home/forge/*")...,
		)
	case presetDigitalOcean:
		return append([]string{"/var/www/laravel"}, append(globMatches(inspector, "/var/www/*"), globMatches(inspector, "/srv/www/*")...)...)
	case presetAAPanel:
		return append(
			globMatches(inspector, "/www/wwwroot/*/current"),
			globMatches(inspector, "/www/wwwroot/*")...,
		)
	case presetCPanel:
		return append(
			globMatches(inspector, "/home/*/*/current"),
			append(globMatches(inspector, "/home/*/laravel/*"), globMatches(inspector, "/home/*/apps/*")...)...,
		)
	default:
		return []string{"/var/www/laravel"}
	}
}

func cpanelNginxConfigPatterns(inspector hostInspector) []string {
	patterns := []string{}
	if pathExists(inspector, "/etc/nginx/conf.d/users") {
		patterns = append(patterns,
			"/etc/nginx/conf.d/users/*.conf",
			"/etc/nginx/conf.d/users/*/*.conf",
		)
	}
	if pathExists(inspector, "/etc/nginx/conf.d/server-includes") {
		patterns = append(patterns, "/etc/nginx/conf.d/server-includes/*.conf")
	}
	if pathExists(inspector, "/etc/nginx/conf.d/server-includes-standalone") {
		patterns = append(patterns, "/etc/nginx/conf.d/server-includes-standalone/*.conf")
	}
	if pathExists(inspector, "/etc/nginx/conf.d") {
		patterns = append(patterns, "/etc/nginx/conf.d/ea-nginx.conf")
	}

	return dedupeSorted(patterns)
}

func defaultScanRoots(preset configPreset) []string {
	switch preset {
	case presetForge:
		return []string{"/home/forge"}
	case presetDigitalOcean:
		return []string{"/var/www", "/srv/www", "/home"}
	case presetAAPanel:
		return []string{"/www/wwwroot"}
	case presetCPanel:
		return []string{"/home"}
	default:
		return []string{"/var/www", "/srv/www"}
	}
}

func detectedHostname(inspector hostInspector) string {
	if inspector.hostname == nil {
		return ""
	}
	hostname, err := inspector.hostname()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(hostname)
}

func detectOSFamily(inspector hostInspector) string {
	if inspector.readFile == nil {
		return "auto"
	}
	contents, err := inspector.readFile("/etc/os-release")
	if err != nil {
		return "auto"
	}

	info := strings.ToLower(string(contents))
	for _, marker := range []string{"id=ubuntu", "id=debian", "id_like=debian"} {
		if strings.Contains(info, marker) {
			return "debian"
		}
	}
	for _, marker := range []string{"id=fedora", "id=rhel", "id=centos", "id=rocky", "id=almalinux", "id_like=\"rhel fedora\"", "id_like=rhel"} {
		if strings.Contains(info, marker) {
			return "rhel"
		}
	}

	return "auto"
}

func detectLaravelAppPath(inspector hostInspector) string {
	if inspector.getwd == nil {
		return ""
	}
	workingDirectory, err := inspector.getwd()
	if err != nil {
		return ""
	}
	workingDirectory = filepath.Clean(workingDirectory)
	if looksLikeLaravelApp(inspector, workingDirectory) {
		return workingDirectory
	}
	parentDirectory := filepath.Dir(workingDirectory)
	if filepath.Base(workingDirectory) == "public" && parentDirectory != workingDirectory && looksLikeLaravelApp(inspector, parentDirectory) {
		return parentDirectory
	}

	return ""
}

func looksLikeLaravelApp(inspector hostInspector, root string) bool {
	for _, candidate := range []string{
		filepath.Join(root, "artisan"),
		filepath.Join(root, "composer.json"),
		filepath.Join(root, "bootstrap", "app.php"),
	} {
		if !pathExists(inspector, candidate) {
			return false
		}
	}

	return true
}

func pathExists(inspector hostInspector, path string) bool {
	if inspector.stat == nil {
		return false
	}
	_, err := inspector.stat(path)
	return err == nil
}

func globHasMatch(inspector hostInspector, pattern string) bool {
	return len(globMatches(inspector, pattern)) != 0
}

func globMatches(inspector hostInspector, pattern string) []string {
	if inspector.glob == nil {
		return nil
	}
	matches, err := inspector.glob(pattern)
	if err != nil {
		return nil
	}
	return dedupeSorted(matches)
}

func dedupeSorted(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	unique := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		clean := filepath.Clean(trimmed)
		if _, found := seen[clean]; found {
			continue
		}
		seen[clean] = struct{}{}
		unique = append(unique, clean)
	}
	sort.Strings(unique)
	return unique
}

func resolveGeneratedConfigPath(path string) string {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		trimmed = defaultGeneratedConfigPath
	}
	return filepath.Clean(trimmed)
}

func writeGeneratedConfigFile(path string, config model.AuditConfig, mode string, stdout io.Writer) error {
	if err := ensureGeneratedConfigPath(path); err != nil {
		return err
	}

	contents, err := renderGeneratedConfigYAML(config, mode)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, contents, 0o644); err != nil {
		return err
	}

	_, err = fmt.Fprintf(stdout, "Wrote %s\n", path)
	return err
}

func ensureGeneratedConfigPath(path string) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("config file %q already exists", path)
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}

	directory := filepath.Dir(path)
	if directory == "." {
		return nil
	}
	return os.MkdirAll(directory, 0o755)
}

func renderGeneratedConfigYAML(config model.AuditConfig, mode string) ([]byte, error) {
	timeout := config.CommandTimeout.String()
	maxOutput := config.MaxOutputBytes
	workerLimit := config.WorkerLimit
	format := config.Format
	verbosity := string(config.Verbosity)
	scope := string(config.Scope)
	interactive := config.Interactive
	color := string(config.ColorMode)
	screenReader := config.ScreenReader
	useDefaultPaths := config.Profile.Paths.UseDefaultPatterns
	discoverNginx := config.Profile.Switches.DiscoverNginx
	discoverPHPFPM := config.Profile.Switches.DiscoverPHPFPM
	discoverSupervisor := config.Profile.Switches.DiscoverSupervisor
	discoverSystemd := config.Profile.Switches.DiscoverSystemd

	fileCfg := fileConfig{
		Version: ptr(1),
		Server: &fileServerConfig{
			Name: maybePtr(config.Profile.Name),
			OS:   maybePtr(config.Profile.OSFamily),
		},
		Laravel: &fileLaravelConfig{
			Scope:     &scope,
			AppPath:   maybePtr(config.AppPath),
			ScanRoots: cloneStrings(config.Profile.Paths.AppScanRoots),
		},
		Services: &fileServicesConfig{
			UseDefaultPaths: &useDefaultPaths,
			Nginx: &fileServicePaths{
				Enabled: &discoverNginx,
				Binary:  maybePtr(config.Profile.Commands.NginxBinary),
				Paths:   cloneStrings(config.Profile.Paths.NginxConfigPatterns),
			},
			PHPFPM: &fileServicePaths{
				Enabled:  &discoverPHPFPM,
				Binaries: cloneStrings(config.Profile.Commands.PHPFPMBinaries),
				Paths:    cloneStrings(config.Profile.Paths.PHPFPMPoolPatterns),
			},
			Supervisor: &fileServicePaths{
				Enabled: &discoverSupervisor,
				Binary:  maybePtr(config.Profile.Commands.SupervisorBinary),
				Paths:   cloneStrings(config.Profile.Paths.SupervisorConfigPatterns),
			},
			Systemd: &fileServicePaths{
				Enabled: &discoverSystemd,
				Paths:   cloneStrings(config.Profile.Paths.SystemdUnitPatterns),
			},
		},
		Output: &fileOutputConfig{
			Format:       &format,
			Verbosity:    &verbosity,
			Interactive:  &interactive,
			Color:        &color,
			ScreenReader: &screenReader,
		},
		Advanced: &fileAdvancedConfig{
			CommandTimeout: &timeout,
			MaxOutputBytes: &maxOutput,
			WorkerLimit:    &workerLimit,
		},
	}

	encoded, err := yaml.Marshal(fileCfg)
	if err != nil {
		return nil, err
	}

	header := fmt.Sprintf("# Generated by larainspect %s. Review paths and service binaries before the first audit.\n\n", mode)
	return append([]byte(header), encoded...), nil
}

func maybePtr(value string) *string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil
	}
	return &trimmed
}

func ptr[T any](value T) *T {
	return &value
}

func printInitHelp(writer io.Writer) {
	fmt.Fprint(writer, strings.TrimSpace(ux.InitHelp()))
	fmt.Fprintln(writer)
}

func printSetupHelp(writer io.Writer) {
	fmt.Fprint(writer, strings.TrimSpace(ux.SetupHelp()))
	fmt.Fprintln(writer)
}

func writeGeneratedConfigUsageError(stderr io.Writer, err error, usage func(io.Writer)) int {
	newUsageError(err, usage).write(stderr)
	return int(model.ExitCodeUsageError)
}
