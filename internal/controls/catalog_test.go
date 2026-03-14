package controls_test

import (
	"slices"
	"testing"

	"github.com/nagi1/larainspect/internal/checks"
	"github.com/nagi1/larainspect/internal/controls"
)

func TestCatalogValidatesAgainstRegisteredChecks(t *testing.T) {
	t.Parallel()

	registered := []string{}
	for _, check := range checks.Registered() {
		registered = append(registered, check.ID())
	}

	if issues := controls.ValidateCatalog(registered); len(issues) > 0 {
		t.Fatalf("ValidateCatalog() issues = %v", issues)
	}
}

func TestForFindingPrefersFindingPrefixMatches(t *testing.T) {
	t.Parallel()

	matched := controls.ForFinding(
		"filesystem.permissions",
		"filesystem.permissions.runtime_owned_env.var.www.shop.env",
	)
	if len(matched) == 0 {
		t.Fatal("expected controls for runtime_owned_env finding")
	}

	ids := []string{}
	for _, control := range matched {
		ids = append(ids, control.ID)
	}

	if !slices.Contains(ids, "laravel.env-integrity-and-permissions") {
		t.Fatalf("expected env integrity control, got %v", ids)
	}
	if slices.Contains(ids, "laravel.permission-shape-baseline") {
		t.Fatalf("did not expect generic permission-shape fallback when exact finding match exists, got %v", ids)
	}
}

func TestFilterByStatusAndCheckID(t *testing.T) {
	t.Parallel()

	filtered := controls.Filter([]controls.Status{controls.StatusImplemented}, []string{"nginx.boundaries"})
	if len(filtered) == 0 {
		t.Fatal("expected nginx controls")
	}

	for _, control := range filtered {
		if control.Status != controls.StatusImplemented {
			t.Fatalf("expected implemented control, got %s", control.Status)
		}

		foundCheck := false
		for _, checkID := range control.CheckIDs {
			if checkID == "nginx.boundaries" {
				foundCheck = true
				break
			}
		}
		if !foundCheck {
			t.Fatalf("expected nginx.boundaries in %+v", control.CheckIDs)
		}
	}
}

func TestCatalogAccessorsAndStatusHelpers(t *testing.T) {
	t.Parallel()

	allControls := controls.All()
	if len(allControls) == 0 {
		t.Fatal("expected controls")
	}

	firstControl := allControls[0]
	byID, found := controls.ByID(firstControl.ID)
	if !found || byID.ID != firstControl.ID {
		t.Fatalf("expected ByID to find %q, got %+v found=%v", firstControl.ID, byID, found)
	}

	checkControls := controls.ForCheckID("operations.hardening")
	if len(checkControls) == 0 {
		t.Fatal("expected hardening controls")
	}

	status, ok := controls.NormalizeStatus("Out-Of-Scope")
	if !ok || status != controls.StatusOutOfScope {
		t.Fatalf("expected normalized out_of_scope, got %q ok=%v", status, ok)
	}
	if _, ok := controls.NormalizeStatus("nope"); ok {
		t.Fatal("expected invalid status normalization to fail")
	}

	sortedStatuses := controls.SortedStatuses()
	if len(sortedStatuses) != 4 || sortedStatuses[0] != controls.StatusImplemented || sortedStatuses[3] != controls.StatusOutOfScope {
		t.Fatalf("unexpected statuses order: %v", sortedStatuses)
	}

	unsorted := []controls.Control{
		{ID: "z"},
		{ID: "a"},
	}
	controls.SortByID(unsorted)
	if unsorted[0].ID != "a" || unsorted[1].ID != "z" {
		t.Fatalf("unexpected sorted controls: %+v", unsorted)
	}
}

func TestForFindingMapsNewPHPFPMBoundaryAndRuntimeFindings(t *testing.T) {
	t.Parallel()

	socketControls := controls.ForFinding(
		"phpfpm.security",
		"phpfpm.security.socket_acl_not_aligned.etc.php.8.3.fpm.pool.d.shop.conf.shop",
	)
	if len(socketControls) == 0 {
		t.Fatal("expected php-fpm socket controls")
	}

	socketIDs := []string{}
	for _, control := range socketControls {
		socketIDs = append(socketIDs, control.ID)
	}
	if !slices.Contains(socketIDs, "phpfpm.socket-and-listener-boundary") {
		t.Fatalf("expected socket boundary control, got %v", socketIDs)
	}

	runtimeControls := controls.ForFinding(
		"phpfpm.security",
		"phpfpm.security.clear_env_disabled.etc.php.8.3.fpm.pool.d.shop.conf.shop",
	)
	if len(runtimeControls) == 0 {
		t.Fatal("expected php-fpm runtime controls")
	}

	runtimeIDs := []string{}
	for _, control := range runtimeControls {
		runtimeIDs = append(runtimeIDs, control.ID)
	}
	if !slices.Contains(runtimeIDs, "phpfpm.runtime-environment-boundary") {
		t.Fatalf("expected runtime environment control, got %v", runtimeIDs)
	}
}

func TestForFindingMapsDeployAndRecoveryDriftControls(t *testing.T) {
	t.Parallel()

	deployControls := controls.ForFinding(
		"operations.deploy",
		"operations.deploy.post_deploy_drift.var.www.shop.current",
	)
	if len(deployControls) == 0 {
		t.Fatal("expected post-deploy drift controls")
	}

	deployIDs := []string{}
	for _, control := range deployControls {
		deployIDs = append(deployIDs, control.ID)
	}
	if !slices.Contains(deployIDs, "deploy.post-deploy-drift-verification") {
		t.Fatalf("expected deploy drift control, got %v", deployIDs)
	}

	recoveryControls := controls.ForFinding(
		"operations.deploy",
		"operations.deploy.post_restore_drift.var.www.shop.current",
	)
	if len(recoveryControls) == 0 {
		t.Fatal("expected post-restore drift controls")
	}

	recoveryIDs := []string{}
	for _, control := range recoveryControls {
		recoveryIDs = append(recoveryIDs, control.ID)
	}
	if !slices.Contains(recoveryIDs, "recovery.backup-and-restore-permission-integrity") {
		t.Fatalf("expected recovery drift control, got %v", recoveryIDs)
	}
}

func TestForFindingMapsOperationalHardeningExtensions(t *testing.T) {
	t.Parallel()

	sshControls := controls.ForFinding(
		"operations.hardening",
		"operations.hardening.runtime_ssh_access.var.www.shop.current.deploy",
	)
	if len(sshControls) == 0 {
		t.Fatal("expected runtime ssh controls")
	}

	sshIDs := []string{}
	for _, control := range sshControls {
		sshIDs = append(sshIDs, control.ID)
	}
	if !slices.Contains(sshIDs, "operations.ssh-access-hygiene") {
		t.Fatalf("expected ssh hygiene control, got %v", sshIDs)
	}

	sudoControls := controls.ForFinding(
		"operations.hardening",
		"operations.hardening.wildcard_sudo.etc.sudoers.d.deploy",
	)
	if len(sudoControls) == 0 {
		t.Fatal("expected wildcard sudo controls")
	}

	sudoIDs := []string{}
	for _, control := range sudoControls {
		sudoIDs = append(sudoIDs, control.ID)
	}
	if !slices.Contains(sudoIDs, "operations.sudo-minimization") {
		t.Fatalf("expected sudo minimization control, got %v", sudoIDs)
	}

	serviceControls := controls.ForFinding(
		"operations.hardening",
		"operations.hardening.laravel_writable_boundary.etc.systemd.system.worker.service.var.www.shop.current",
	)
	if len(serviceControls) == 0 {
		t.Fatal("expected writable boundary controls")
	}

	serviceIDs := []string{}
	for _, control := range serviceControls {
		serviceIDs = append(serviceIDs, control.ID)
	}
	if !slices.Contains(serviceIDs, "services.systemd-writable-path-confinement") {
		t.Fatalf("expected systemd writable-path control, got %v", serviceIDs)
	}
}
