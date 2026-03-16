package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nagi1/larainspect/internal/model"
)

func TestRunPopulateCommandFillsMissingValuesWithoutOverwritingExistingOnes(t *testing.T) {
	t.Parallel()

	configPath := filepath.Join(t.TempDir(), "larainspect.yaml")
	writeConfigFileForTest(t, configPath, strings.Join([]string{
		"version: 1",
		"server:",
		"  name: keep-me",
		"laravel:",
		"  app_path: /home/alice/apps/shop/current",
		"identities:",
		"  deploy_users:",
		"    - custom-deploy",
	}, "\n"))

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	inspector := hostInspector{
		hostname: func() (string, error) { return "detected-host", nil },
		stat: func(path string) (fs.FileInfo, error) {
			switch path {
			case "/etc/nginx/nginx.conf":
				return fakeFileInfo{name: filepath.Base(path)}, nil
			default:
				return nil, fs.ErrNotExist
			}
		},
		glob: func(pattern string) ([]string, error) {
			if pattern == "/etc/php/*/fpm/pool.d/*.conf" {
				return []string{"/etc/php/8.3/fpm/pool.d/shop.conf"}, nil
			}
			return nil, nil
		},
		readFile: func(path string) ([]byte, error) {
			switch path {
			case "/etc/os-release":
				return []byte("ID=ubuntu\n"), nil
			case "/etc/nginx/nginx.conf":
				return []byte("user www-data www-data;\n"), nil
			case "/etc/php/8.3/fpm/pool.d/shop.conf":
				return []byte("[shop]\nuser = app\ngroup = app\n"), nil
			default:
				return nil, fs.ErrNotExist
			}
		},
		lookupOwner: func(path string) (string, error) { return "alice", nil },
	}

	exitCode := runPopulateCommandWithInspector(strings.NewReader(""), &stdout, &stderr, populateConfigOptions{path: configPath}, inspector)
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d stderr=%q", exitCode, stderr.String())
	}

	contents, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	rendered := string(contents)
	if !strings.Contains(rendered, "name: keep-me") {
		t.Fatalf("expected existing server name to be preserved, got %q", rendered)
	}
	if !strings.Contains(rendered, "- custom-deploy") {
		t.Fatalf("expected existing deploy user to be preserved, got %q", rendered)
	}
	if !strings.Contains(rendered, "runtime_users:") || !strings.Contains(rendered, "- app") {
		t.Fatalf("expected runtime identities to be populated, got %q", rendered)
	}
	if !strings.Contains(rendered, "web_users:") || !strings.Contains(rendered, "- www-data") {
		t.Fatalf("expected web identities to be populated, got %q", rendered)
	}
	if !strings.Contains(stdout.String(), "Updated ") {
		t.Fatalf("expected success output, got %q", stdout.String())
	}
}

func TestRunPopulateCommandInteractiveCompletesMissingIdentities(t *testing.T) {
	t.Parallel()

	configPath := filepath.Join(t.TempDir(), "larainspect.yaml")
	writeConfigFileForTest(t, configPath, "version: 1\n")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	inspector := hostInspector{
		readFile: func(path string) ([]byte, error) {
			if path == "/etc/os-release" {
				return []byte("ID=ubuntu\n"), nil
			}
			return nil, fs.ErrNotExist
		},
		stat: func(path string) (fs.FileInfo, error) { return nil, fs.ErrNotExist },
	}

	input := strings.NewReader("deploy\nruntime\nruntime-group\nweb\nweb-group\n")
	exitCode := runPopulateCommandWithInspector(input, &stdout, &stderr, populateConfigOptions{path: configPath, interactive: true}, inspector)
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d stderr=%q", exitCode, stderr.String())
	}

	contents, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	rendered := string(contents)
	if !strings.Contains(rendered, "- deploy") || !strings.Contains(rendered, "- web-group") {
		t.Fatalf("expected prompted identities in config, got %q", rendered)
	}
}

func TestRunPopulateCommandRequiresExistingConfig(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := runPopulateCommandWithInspector(strings.NewReader(""), &stdout, &stderr, populateConfigOptions{}, hostInspector{})
	if exitCode == 0 {
		t.Fatal("expected non-zero exit code when no config file is present")
	}
	if !strings.Contains(stderr.String(), "no config file found") {
		t.Fatalf("expected missing config guidance, got %q", stderr.String())
	}
}

func TestRunPopulateCommandRejectsInvalidPresetAndBrokenConfig(t *testing.T) {
	t.Parallel()

	t.Run("invalid preset", func(t *testing.T) {
		configPath := filepath.Join(t.TempDir(), "larainspect.yaml")
		writeConfigFileForTest(t, configPath, "version: 1\n")

		var stdout bytes.Buffer
		var stderr bytes.Buffer
		exitCode := runPopulateCommandWithInspector(strings.NewReader(""), &stdout, &stderr, populateConfigOptions{path: configPath, preset: "bad-preset"}, hostInspector{})
		if exitCode == 0 {
			t.Fatal("expected invalid preset to fail")
		}
		if !strings.Contains(stderr.String(), "unsupported preset") {
			t.Fatalf("expected preset validation error, got %q", stderr.String())
		}
	})

	t.Run("broken config", func(t *testing.T) {
		configPath := filepath.Join(t.TempDir(), "larainspect.yaml")
		writeConfigFileForTest(t, configPath, "version: [\n")

		var stdout bytes.Buffer
		var stderr bytes.Buffer
		exitCode := runPopulateCommandWithInspector(strings.NewReader(""), &stdout, &stderr, populateConfigOptions{path: configPath}, hostInspector{})
		if exitCode == 0 {
			t.Fatal("expected invalid config to fail")
		}
		if !strings.Contains(stderr.String(), "parse config file") {
			t.Fatalf("expected parse error, got %q", stderr.String())
		}
	})
}

func TestAppRunPopulateCommand(t *testing.T) {
	t.Parallel()

	configPath := filepath.Join(t.TempDir(), "larainspect.yaml")
	writeConfigFileForTest(t, configPath, "version: 1\n")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := NewAppWithInput(strings.NewReader(""), &stdout, &stderr)
	exitCode := app.Run(context.Background(), []string{"populate", "--config", configPath})
	if exitCode != 0 {
		t.Fatalf("expected populate command to succeed, got %d stderr=%q", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Updated ") {
		t.Fatalf("expected populate command output, got %q", stdout.String())
	}
}

func TestNewPopulateCommandHelpAndFlagError(t *testing.T) {
	t.Parallel()

	app := App{stdin: strings.NewReader(""), stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}}
	cmd := app.newPopulateCommand()

	var helpOutput bytes.Buffer
	cmd.SetOut(&helpOutput)
	cmd.SetErr(&helpOutput)
	if err := cmd.Help(); err != nil {
		t.Fatalf("Help() error = %v", err)
	}
	if !strings.Contains(helpOutput.String(), "larainspect populate") {
		t.Fatalf("expected populate help output, got %q", helpOutput.String())
	}

	cmd = app.newPopulateCommand()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"--bad-flag"})
	err := cmd.ExecuteContext(context.Background())
	if err == nil {
		t.Fatal("expected bad flag to return an error")
	}
	var cmdErr *commandError
	if !errors.As(err, &cmdErr) {
		t.Fatalf("expected commandError, got %T", err)
	}
}

func TestLoadRawConfigFileAndWritePopulatedConfigFile(t *testing.T) {
	t.Parallel()

	t.Run("invalid version rejected", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "larainspect.yaml")
		writeConfigFileForTest(t, path, "version: 2\n")

		_, err := loadRawConfigFile(path)
		if err == nil || !strings.Contains(err.Error(), "unsupported config version") {
			t.Fatalf("expected unsupported version error, got %v", err)
		}
	})

	t.Run("json write path", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "larainspect.json")
		var stdout bytes.Buffer

		err := writePopulatedConfigFile(path, fileConfig{Server: &fileServerConfig{Name: ptr("json-host")}}, &stdout)
		if err != nil {
			t.Fatalf("writePopulatedConfigFile() error = %v", err)
		}

		contents, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatalf("ReadFile() error = %v", readErr)
		}
		if !strings.Contains(string(contents), "\"name\": \"json-host\"") {
			t.Fatalf("expected JSON output, got %q", string(contents))
		}
		if !strings.Contains(stdout.String(), "Updated ") {
			t.Fatalf("expected success output, got %q", stdout.String())
		}
	})
}

func TestMergeMissingAuditConfigAndPopulateHelpers(t *testing.T) {
	t.Parallel()

	inferred := model.AuditConfig{
		Scope:   model.ScanScopeApp,
		AppPath: "/srv/www/app/current",
		Profile: model.HostProfile{
			Name:     "detected-host",
			OSFamily: "debian",
			Paths: model.DiscoveryPaths{
				UseDefaultPatterns:       true,
				AppScanRoots:             []string{"/srv/www/app/current", "/srv/www/app/shared"},
				NginxConfigPatterns:      []string{"/etc/nginx/nginx.conf"},
				PHPFPMPoolPatterns:       []string{"/etc/php/*/fpm/pool.d/*.conf"},
				MySQLConfigPatterns:      []string{"/etc/mysql/my.cnf"},
				SupervisorConfigPatterns: []string{"/etc/supervisor/conf.d/*.conf"},
				SystemdUnitPatterns:      []string{"/etc/systemd/system/*.service"},
			},
			Commands: model.DiscoveryCommands{
				NginxBinary:      "/usr/sbin/nginx",
				PHPFPMBinaries:   []string{"php-fpm8.3", "php-fpm"},
				SupervisorBinary: "/usr/bin/supervisord",
			},
			Switches: model.DiscoverySwitches{
				DiscoverNginx:      true,
				DiscoverPHPFPM:     true,
				DiscoverMySQL:      true,
				DiscoverSupervisor: true,
				DiscoverSystemd:    true,
			},
		},
	}

	merged := mergeMissingAuditConfig(model.AuditConfig{}, inferred)
	if merged.Profile.Name != inferred.Profile.Name || merged.Profile.Commands.NginxBinary != inferred.Profile.Commands.NginxBinary {
		t.Fatalf("expected inferred values to be merged, got %#v", merged)
	}

	config := fileConfig{}
	populateMissingFileConfig(&config, merged, model.IdentityConfig{
		DeployUsers:   []string{"deploy"},
		RuntimeUsers:  []string{"app"},
		RuntimeGroups: []string{"app"},
		WebUsers:      []string{"www-data"},
		WebGroups:     []string{"www-data"},
	})

	if config.Server == nil || config.Services == nil || config.Identities == nil {
		t.Fatalf("expected populateMissingFileConfig to create sections, got %#v", config)
	}
	if config.Services.Nginx == nil || config.Services.PHPFPM == nil || config.Services.Supervisor == nil {
		t.Fatalf("expected service sections to be populated, got %#v", config.Services)
	}
	if config.Services.Nginx.Binary == nil || *config.Services.Nginx.Binary != "/usr/sbin/nginx" {
		t.Fatalf("expected nginx binary to be populated, got %#v", config.Services.Nginx)
	}
	if len(config.Services.PHPFPM.Binaries) == 0 {
		t.Fatalf("expected php-fpm binaries to be populated, got %#v", config.Services.PHPFPM)
	}

	service := &fileServicePaths{}
	populateServicePaths(&service, true, nil, "", nil)
	if service.Enabled != nil || len(service.Paths) != 0 {
		t.Fatalf("expected no-op populateServicePaths call to keep section unchanged, got %#v", service)
	}

	service = nil
	populateServicePaths(&service, true, []string{"/etc/test.conf"}, "binary", []string{"bin-a"})
	if service == nil || service.Enabled == nil || service.Binary == nil || len(service.Binaries) == 0 {
		t.Fatalf("expected service paths to be populated, got %#v", service)
	}

	config = fileConfig{}
	populateServerConfig(&config, model.AuditConfig{})
	if config.Server != nil {
		t.Fatalf("expected empty server inference to skip section creation, got %#v", config.Server)
	}
}
