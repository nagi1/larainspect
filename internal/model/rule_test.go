package model_test

import (
	"testing"

	"github.com/nagi1/larainspect/internal/model"
)

func TestRuleConfigNormalizationHelpers(t *testing.T) {
	t.Parallel()

	config := model.RuleConfig{
		Enable:     []string{" two ", "one", "one"},
		Disable:    []string{" three ", "three"},
		CustomDirs: []string{" /tmp/b ", "/tmp/a", "/tmp/a"},
	}

	enable := config.NormalizedEnable()
	if len(enable) != 2 || enable[0] != "one" || enable[1] != "two" {
		t.Fatalf("NormalizedEnable() = %+v", enable)
	}

	disable := config.NormalizedDisable()
	if len(disable) != 1 || disable[0] != "three" {
		t.Fatalf("NormalizedDisable() = %+v", disable)
	}

	customDirs := config.NormalizedCustomDirs()
	if len(customDirs) != 2 || customDirs[0] != "/tmp/a" || customDirs[1] != "/tmp/b" {
		t.Fatalf("NormalizedCustomDirs() = %+v", customDirs)
	}
}

func TestRuleDefinitionDefaultsAndTargets(t *testing.T) {
	t.Parallel()

	rule := model.RuleDefinition{}
	if rule.EffectiveConfidence() != model.ConfidencePossible {
		t.Fatalf("EffectiveConfidence() = %q", rule.EffectiveConfidence())
	}
	if rule.EffectiveClass() != model.FindingClassHeuristic {
		t.Fatalf("EffectiveClass() = %q", rule.EffectiveClass())
	}
	if !rule.IsEnabled() {
		t.Fatal("expected nil enabled to default true")
	}

	enabled := false
	rule.Enabled = &enabled
	if rule.IsEnabled() {
		t.Fatal("expected explicit enabled=false")
	}

	targets := (model.RulePattern{
		Target:  "php-files",
		Targets: []string{"blade-files", "php-files", " routes-files "},
	}).EffectiveTargets()
	if len(targets) != 3 || targets[0] != "php-files" || targets[1] != "blade-files" || targets[2] != "routes-files" {
		t.Fatalf("EffectiveTargets() = %+v", targets)
	}
}

func TestSortHelpersCoverRuleAdjacentModelPaths(t *testing.T) {
	t.Parallel()

	nginxSites := []model.NginxSite{{ConfigPath: "b", Root: "b"}, {ConfigPath: "a", Root: "a"}}
	model.SortNginxSites(nginxSites)
	if nginxSites[0].ConfigPath != "a" {
		t.Fatalf("SortNginxSites() = %+v", nginxSites)
	}

	pools := []model.PHPFPMPool{{ConfigPath: "b", Name: "b"}, {ConfigPath: "a", Name: "a"}}
	model.SortPHPFPMPools(pools)
	if pools[0].ConfigPath != "a" {
		t.Fatalf("SortPHPFPMPools() = %+v", pools)
	}
	pools = []model.PHPFPMPool{{ConfigPath: "a", Name: "b"}, {ConfigPath: "a", Name: "a"}}
	model.SortPHPFPMPools(pools)
	if pools[0].Name != "a" {
		t.Fatalf("SortPHPFPMPools() secondary = %+v", pools)
	}

	programs := []model.SupervisorProgram{{ConfigPath: "b", Name: "b"}, {ConfigPath: "a", Name: "a"}}
	model.SortSupervisorPrograms(programs)
	if programs[0].ConfigPath != "a" {
		t.Fatalf("SortSupervisorPrograms() = %+v", programs)
	}
	programs = []model.SupervisorProgram{{ConfigPath: "a", Name: "b"}, {ConfigPath: "a", Name: "a"}}
	model.SortSupervisorPrograms(programs)
	if programs[0].Name != "a" {
		t.Fatalf("SortSupervisorPrograms() secondary = %+v", programs)
	}

	servers := []model.SupervisorHTTPServer{{ConfigPath: "b", Bind: "b"}, {ConfigPath: "a", Bind: "a"}}
	model.SortSupervisorHTTPServers(servers)
	if servers[0].ConfigPath != "a" {
		t.Fatalf("SortSupervisorHTTPServers() = %+v", servers)
	}
	servers = []model.SupervisorHTTPServer{{ConfigPath: "a", Bind: "b"}, {ConfigPath: "a", Bind: "a"}}
	model.SortSupervisorHTTPServers(servers)
	if servers[0].Bind != "a" {
		t.Fatalf("SortSupervisorHTTPServers() secondary = %+v", servers)
	}

	units := []model.SystemdUnit{{Path: "b", Name: "b"}, {Path: "a", Name: "a"}}
	model.SortSystemdUnits(units)
	if units[0].Path != "a" {
		t.Fatalf("SortSystemdUnits() = %+v", units)
	}
	units = []model.SystemdUnit{{Path: "a", Name: "b"}, {Path: "a", Name: "a"}}
	model.SortSystemdUnits(units)
	if units[0].Name != "a" {
		t.Fatalf("SortSystemdUnits() secondary = %+v", units)
	}

	cronEntries := []model.CronEntry{{SourcePath: "b", Schedule: "b", Command: "b"}, {SourcePath: "a", Schedule: "a", Command: "a"}}
	model.SortCronEntries(cronEntries)
	if cronEntries[0].SourcePath != "a" {
		t.Fatalf("SortCronEntries() = %+v", cronEntries)
	}
	cronEntries = []model.CronEntry{{SourcePath: "a", Schedule: "b", Command: "b"}, {SourcePath: "a", Schedule: "a", Command: "a"}}
	model.SortCronEntries(cronEntries)
	if cronEntries[0].Schedule != "a" {
		t.Fatalf("SortCronEntries() secondary = %+v", cronEntries)
	}
	cronEntries = []model.CronEntry{{SourcePath: "a", Schedule: "a", Command: "b"}, {SourcePath: "a", Schedule: "a", Command: "a"}}
	model.SortCronEntries(cronEntries)
	if cronEntries[0].Command != "a" {
		t.Fatalf("SortCronEntries() tertiary = %+v", cronEntries)
	}

	listeners := []model.ListenerRecord{{Protocol: "tcp", LocalPort: "443", LocalAddress: "b"}, {Protocol: "tcp", LocalPort: "80", LocalAddress: "a"}}
	model.SortListenerRecords(listeners)
	if listeners[0].LocalPort != "443" {
		t.Fatalf("SortListenerRecords() = %+v", listeners)
	}
	listeners = []model.ListenerRecord{{Protocol: "tcp", LocalPort: "80", LocalAddress: "b"}, {Protocol: "tcp", LocalPort: "80", LocalAddress: "a"}}
	model.SortListenerRecords(listeners)
	if listeners[0].LocalAddress != "a" {
		t.Fatalf("SortListenerRecords() tertiary = %+v", listeners)
	}

	sudoRules := []model.SudoRule{{Path: "b", Principal: "b"}, {Path: "a", Principal: "a"}}
	model.SortSudoRules(sudoRules)
	if sudoRules[0].Path != "a" {
		t.Fatalf("SortSudoRules() = %+v", sudoRules)
	}
	sudoRules = []model.SudoRule{{Path: "a", Principal: "b"}, {Path: "a", Principal: "a"}}
	model.SortSudoRules(sudoRules)
	if sudoRules[0].Principal != "a" {
		t.Fatalf("SortSudoRules() secondary = %+v", sudoRules)
	}
}
