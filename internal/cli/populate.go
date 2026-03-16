package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/nagi1/larainspect/internal/model"
	"github.com/nagi1/larainspect/internal/ux"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

type populateConfigOptions struct {
	path        string
	preset      string
	interactive bool
}

func (app App) newPopulateCommand() *cobra.Command {
	var options populateConfigOptions

	cmd := &cobra.Command{
		Use:           "populate",
		Short:         "Fill missing config values in an existing larainspect config",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if exitCode := runPopulateCommandWithInspector(app.stdin, cmd.OutOrStdout(), cmd.ErrOrStderr(), options, newHostInspector()); exitCode != 0 {
				return &commandError{code: exitCode}
			}
			return nil
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&options.path, "config", "", "Path to the existing config file to update")
	flags.BoolVar(&options.interactive, "interactive", false, "Prompt for missing identity values after host inference")
	flags.StringVar(&options.preset, "preset", "", "Skip auto-detection and force a preset")
	cmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		fmt.Fprint(cmd.OutOrStdout(), strings.TrimSpace(ux.PopulateHelp()))
		fmt.Fprintln(cmd.OutOrStdout())
	})
	cmd.SetFlagErrorFunc(func(cmd *cobra.Command, err error) error {
		return newUsageError(err, func(writer io.Writer) {
			fmt.Fprint(writer, strings.TrimSpace(ux.PopulateHelp()))
			fmt.Fprintln(writer)
		})
	})

	return cmd
}

func runPopulateCommandWithInspector(stdin io.Reader, stdout io.Writer, stderr io.Writer, options populateConfigOptions, inspector hostInspector) int {
	configPath, err := resolveAuditConfigFilePath(options.path)
	if err != nil {
		return writeGeneratedConfigUsageError(stderr, err, func(writer io.Writer) {
			fmt.Fprint(writer, strings.TrimSpace(ux.PopulateHelp()))
			fmt.Fprintln(writer)
		})
	}
	if configPath == "" {
		return writeGeneratedConfigUsageError(stderr, fmt.Errorf("no config file found; use --config or run larainspect init/setup first"), func(writer io.Writer) {
			fmt.Fprint(writer, strings.TrimSpace(ux.PopulateHelp()))
			fmt.Fprintln(writer)
		})
	}

	parsedConfig, err := loadRawConfigFile(configPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return int(model.ExitCodeUsageError)
	}

	currentConfig, err := applyFileConfig(configPath, parsedConfig)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return int(model.ExitCodeUsageError)
	}

	preset, err := resolveRequestedPreset(options.preset)
	if err != nil {
		return writeGeneratedConfigUsageError(stderr, err, func(writer io.Writer) {
			fmt.Fprint(writer, strings.TrimSpace(ux.PopulateHelp()))
			fmt.Fprintln(writer)
		})
	}
	if preset == "" {
		if guess, detected := detectHostingPreset(inspector); detected {
			preset = guess.preset
		}
	}

	inferredConfig := buildGeneratedConfig(preset, inspector, generatedAnswers{
		osFamily: currentConfig.Profile.OSFamily,
		scope:    currentConfig.Scope,
		appPath:  currentConfig.AppPath,
	})
	mergedConfig := mergeMissingAuditConfig(currentConfig, inferredConfig)
	resolvedIdentities := mergeMissingIdentityConfig(currentConfig.Identities, guessGeneratedIdentityConfig(preset, inspector, mergedConfig))
	if options.interactive && !generatedIdentityConfigComplete(resolvedIdentities) {
		resolvedIdentities, err = promptToCompleteIdentityConfig(stdin, stderr, resolvedIdentities)
		if err != nil {
			return writeGeneratedConfigUsageError(stderr, err, func(writer io.Writer) {
				fmt.Fprint(writer, strings.TrimSpace(ux.PopulateHelp()))
				fmt.Fprintln(writer)
			})
		}
	}

	populateMissingFileConfig(&parsedConfig, mergedConfig, resolvedIdentities)
	if err := writePopulatedConfigFile(configPath, parsedConfig, stdout); err != nil {
		fmt.Fprintln(stderr, err)
		return int(model.ExitCodeUsageError)
	}

	return 0
}

func loadRawConfigFile(path string) (fileConfig, error) {
	fileBytes, err := os.ReadFile(path)
	if err != nil {
		return fileConfig{}, err
	}

	var parsedConfig fileConfig
	if err := decodeConfigFile(path, fileBytes, &parsedConfig); err != nil {
		return fileConfig{}, fmt.Errorf("parse config file %q: %w", path, err)
	}
	if parsedConfig.Version != nil && *parsedConfig.Version != 1 {
		return fileConfig{}, fmt.Errorf("unsupported config version %d", *parsedConfig.Version)
	}

	return parsedConfig, nil
}

func writePopulatedConfigFile(path string, config fileConfig, stdout io.Writer) error {
	config.Version = ptr(1)

	var (
		contents []byte
		err      error
	)
	if isYAMLConfigFile(path) {
		contents, err = yaml.Marshal(config)
	} else {
		contents, err = json.MarshalIndent(config, "", "  ")
		if err == nil {
			contents = append(contents, '\n')
		}
	}
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, contents, 0o644); err != nil {
		return err
	}

	_, err = fmt.Fprintf(stdout, "Updated %s\n", path)
	return err
}

func mergeMissingAuditConfig(current model.AuditConfig, inferred model.AuditConfig) model.AuditConfig {
	merged := current
	if strings.TrimSpace(merged.Profile.Name) == "" {
		merged.Profile.Name = inferred.Profile.Name
	}
	if strings.TrimSpace(merged.Profile.OSFamily) == "" || strings.EqualFold(strings.TrimSpace(merged.Profile.OSFamily), "auto") {
		merged.Profile.OSFamily = inferred.Profile.OSFamily
	}
	if !merged.Scope.Valid() {
		merged.Scope = inferred.Scope
	}
	if strings.TrimSpace(merged.AppPath) == "" {
		merged.AppPath = inferred.AppPath
	}
	if len(merged.Profile.Paths.AppScanRoots) == 0 {
		merged.Profile.Paths.AppScanRoots = cloneStrings(inferred.Profile.Paths.AppScanRoots)
	}
	if len(merged.Profile.Paths.NginxConfigPatterns) == 0 {
		merged.Profile.Paths.NginxConfigPatterns = cloneStrings(inferred.Profile.Paths.NginxConfigPatterns)
	}
	if len(merged.Profile.Paths.PHPFPMPoolPatterns) == 0 {
		merged.Profile.Paths.PHPFPMPoolPatterns = cloneStrings(inferred.Profile.Paths.PHPFPMPoolPatterns)
	}
	if len(merged.Profile.Paths.MySQLConfigPatterns) == 0 {
		merged.Profile.Paths.MySQLConfigPatterns = cloneStrings(inferred.Profile.Paths.MySQLConfigPatterns)
	}
	if len(merged.Profile.Paths.SupervisorConfigPatterns) == 0 {
		merged.Profile.Paths.SupervisorConfigPatterns = cloneStrings(inferred.Profile.Paths.SupervisorConfigPatterns)
	}
	if len(merged.Profile.Paths.SystemdUnitPatterns) == 0 {
		merged.Profile.Paths.SystemdUnitPatterns = cloneStrings(inferred.Profile.Paths.SystemdUnitPatterns)
	}
	if strings.TrimSpace(merged.Profile.Commands.NginxBinary) == "" {
		merged.Profile.Commands.NginxBinary = inferred.Profile.Commands.NginxBinary
	}
	if len(merged.Profile.Commands.PHPFPMBinaries) == 0 {
		merged.Profile.Commands.PHPFPMBinaries = cloneStrings(inferred.Profile.Commands.PHPFPMBinaries)
	}
	if strings.TrimSpace(merged.Profile.Commands.SupervisorBinary) == "" {
		merged.Profile.Commands.SupervisorBinary = inferred.Profile.Commands.SupervisorBinary
	}
	if !merged.Profile.Paths.UseDefaultPatterns {
		merged.Profile.Paths.UseDefaultPatterns = inferred.Profile.Paths.UseDefaultPatterns
	}
	if !merged.Profile.Switches.DiscoverNginx {
		merged.Profile.Switches.DiscoverNginx = inferred.Profile.Switches.DiscoverNginx
	}
	if !merged.Profile.Switches.DiscoverPHPFPM {
		merged.Profile.Switches.DiscoverPHPFPM = inferred.Profile.Switches.DiscoverPHPFPM
	}
	if !merged.Profile.Switches.DiscoverMySQL {
		merged.Profile.Switches.DiscoverMySQL = inferred.Profile.Switches.DiscoverMySQL
	}
	if !merged.Profile.Switches.DiscoverSupervisor {
		merged.Profile.Switches.DiscoverSupervisor = inferred.Profile.Switches.DiscoverSupervisor
	}
	if !merged.Profile.Switches.DiscoverSystemd {
		merged.Profile.Switches.DiscoverSystemd = inferred.Profile.Switches.DiscoverSystemd
	}

	return merged
}

func mergeMissingIdentityConfig(current model.IdentityConfig, inferred model.IdentityConfig) model.IdentityConfig {
	merged := normalizeIdentityConfig(current)
	if len(merged.DeployUsers) == 0 {
		merged.DeployUsers = cloneStrings(inferred.DeployUsers)
	}
	if len(merged.RuntimeUsers) == 0 {
		merged.RuntimeUsers = cloneStrings(inferred.RuntimeUsers)
	}
	if len(merged.RuntimeGroups) == 0 {
		merged.RuntimeGroups = cloneStrings(inferred.RuntimeGroups)
	}
	if len(merged.WebUsers) == 0 {
		merged.WebUsers = cloneStrings(inferred.WebUsers)
	}
	if len(merged.WebGroups) == 0 {
		merged.WebGroups = cloneStrings(inferred.WebGroups)
	}

	return normalizeIdentityConfig(merged)
}

func populateMissingFileConfig(config *fileConfig, inferred model.AuditConfig, identities model.IdentityConfig) {
	if config.Version == nil {
		config.Version = ptr(1)
	}
	populateServerConfig(config, inferred)
	populateLaravelConfig(config, inferred)
	populateIdentitiesConfig(config, identities)
	populateServicesConfig(config, inferred)
}

func populateServerConfig(config *fileConfig, inferred model.AuditConfig) {
	if strings.TrimSpace(inferred.Profile.Name) == "" && strings.TrimSpace(inferred.Profile.OSFamily) == "" {
		return
	}
	if config.Server == nil {
		config.Server = &fileServerConfig{}
	}
	if stringPointerBlank(config.Server.Name) && strings.TrimSpace(inferred.Profile.Name) != "" {
		config.Server.Name = ptr(strings.TrimSpace(inferred.Profile.Name))
	}
	if stringPointerBlank(config.Server.OS) && strings.TrimSpace(inferred.Profile.OSFamily) != "" {
		config.Server.OS = ptr(strings.TrimSpace(inferred.Profile.OSFamily))
	}
}

func populateLaravelConfig(config *fileConfig, inferred model.AuditConfig) {
	if config.Laravel == nil {
		config.Laravel = &fileLaravelConfig{}
	}
	if stringPointerBlank(config.Laravel.Scope) && inferred.Scope.Valid() {
		scope := string(inferred.Scope)
		config.Laravel.Scope = &scope
	}
	if stringPointerBlank(config.Laravel.AppPath) && strings.TrimSpace(inferred.AppPath) != "" {
		config.Laravel.AppPath = ptr(strings.TrimSpace(inferred.AppPath))
	}
	if len(config.Laravel.ScanRoots) == 0 && len(inferred.Profile.Paths.AppScanRoots) > 0 {
		config.Laravel.ScanRoots = cloneStrings(inferred.Profile.Paths.AppScanRoots)
	}
}

func populateIdentitiesConfig(config *fileConfig, identities model.IdentityConfig) {
	identities = normalizeIdentityConfig(identities)
	if len(identities.DeployUsers) == 0 && len(identities.RuntimeUsers) == 0 && len(identities.RuntimeGroups) == 0 && len(identities.WebUsers) == 0 && len(identities.WebGroups) == 0 {
		return
	}
	if config.Identities == nil {
		config.Identities = &fileIdentitiesConfig{}
	}
	if len(config.Identities.DeployUsers) == 0 {
		config.Identities.DeployUsers = cloneStrings(identities.DeployUsers)
	}
	if len(config.Identities.RuntimeUsers) == 0 {
		config.Identities.RuntimeUsers = cloneStrings(identities.RuntimeUsers)
	}
	if len(config.Identities.RuntimeGroups) == 0 {
		config.Identities.RuntimeGroups = cloneStrings(identities.RuntimeGroups)
	}
	if len(config.Identities.WebUsers) == 0 {
		config.Identities.WebUsers = cloneStrings(identities.WebUsers)
	}
	if len(config.Identities.WebGroups) == 0 {
		config.Identities.WebGroups = cloneStrings(identities.WebGroups)
	}
}

func populateServicesConfig(config *fileConfig, inferred model.AuditConfig) {
	if config.Services == nil {
		config.Services = &fileServicesConfig{}
	}
	if config.Services.UseDefaultPaths == nil {
		config.Services.UseDefaultPaths = ptr(inferred.Profile.Paths.UseDefaultPatterns)
	}
	populateServicePaths(&config.Services.Nginx, inferred.Profile.Switches.DiscoverNginx, inferred.Profile.Paths.NginxConfigPatterns, inferred.Profile.Commands.NginxBinary, nil)
	populateServicePaths(&config.Services.PHPFPM, inferred.Profile.Switches.DiscoverPHPFPM, inferred.Profile.Paths.PHPFPMPoolPatterns, "", inferred.Profile.Commands.PHPFPMBinaries)
	populateServicePaths(&config.Services.MySQL, inferred.Profile.Switches.DiscoverMySQL, inferred.Profile.Paths.MySQLConfigPatterns, "", nil)
	populateServicePaths(&config.Services.Supervisor, inferred.Profile.Switches.DiscoverSupervisor, inferred.Profile.Paths.SupervisorConfigPatterns, inferred.Profile.Commands.SupervisorBinary, nil)
	populateServicePaths(&config.Services.Systemd, inferred.Profile.Switches.DiscoverSystemd, inferred.Profile.Paths.SystemdUnitPatterns, "", nil)
}

func populateServicePaths(service **fileServicePaths, enabled bool, paths []string, binary string, binaries []string) {
	if len(paths) == 0 && strings.TrimSpace(binary) == "" && len(binaries) == 0 {
		return
	}
	if *service == nil {
		*service = &fileServicePaths{}
	}
	if (*service).Enabled == nil {
		(*service).Enabled = ptr(enabled)
	}
	if len((*service).Paths) == 0 && len(paths) > 0 {
		(*service).Paths = cloneStrings(paths)
	}
	if stringPointerBlank((*service).Binary) && strings.TrimSpace(binary) != "" {
		(*service).Binary = ptr(strings.TrimSpace(binary))
	}
	if len((*service).Binaries) == 0 && len(binaries) > 0 {
		(*service).Binaries = cloneStrings(binaries)
	}
}

func stringPointerBlank(value *string) bool {
	return value == nil || strings.TrimSpace(*value) == ""
}
