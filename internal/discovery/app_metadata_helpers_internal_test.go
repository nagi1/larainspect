package discovery

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/nagi1/larainspect/internal/model"
)

func TestShouldSkipArtifactDirectory(t *testing.T) {
	t.Parallel()

	cases := []struct {
		path  string
		isDir bool
		want  bool
	}{
		{"vendor", true, true},
		{"vendor/autoload.php", true, true},
		{"node_modules", true, true},
		{"node_modules/axios", true, true},
		{"storage/framework/cache", true, true},
		{"storage/framework/cache/data", true, true},
		{"app", true, false},
		{"vendor", false, false},
	}

	for _, tc := range cases {
		entry := fakeDirEntry{name: tc.path, dir: tc.isDir}
		if got := shouldSkipArtifactDirectory(tc.path, entry); got != tc.want {
			t.Errorf("shouldSkipArtifactDirectory(%q, isDir=%v) = %v, want %v", tc.path, tc.isDir, got, tc.want)
		}
	}
}

func TestMergeInstalledPackages(t *testing.T) {
	t.Parallel()

	app := &model.LaravelApp{}
	mergeInstalledPackages(app, []composerLockPackage{
		{Name: "laravel/framework", Version: "v11.0.0"},
		{Name: "guzzlehttp/guzzle", Version: "7.5.0"},
		{Name: "", Version: "1.0"},
		{Name: "pkg", Version: ""},
	})

	if len(app.InstalledPackages) != 2 {
		t.Fatalf("expected 2 packages, got %d", len(app.InstalledPackages))
	}
	if app.InstalledPackages["laravel/framework"] != "v11.0.0" {
		t.Errorf("expected laravel/framework v11.0.0, got %q", app.InstalledPackages["laravel/framework"])
	}
}

func TestPackageVersionForName(t *testing.T) {
	t.Parallel()

	packages := []model.PackageRecord{
		{Name: "laravel/framework", Version: "v11.0.0"},
		{Name: "livewire/livewire", Version: ""},
	}

	if got := packageVersionForName(packages, "laravel/framework", "^11"); got != "v11.0.0" {
		t.Errorf("expected v11.0.0, got %q", got)
	}
	if got := packageVersionForName(packages, "livewire/livewire", "^3"); got != "^3" {
		t.Errorf("expected fallback, got %q", got)
	}
	if got := packageVersionForName(packages, "missing", "default"); got != "default" {
		t.Errorf("expected default, got %q", got)
	}
}

func TestClassifyFilesystemError(t *testing.T) {
	t.Parallel()

	if got := classifyFilesystemError(fs.ErrPermission); got != model.ErrorKindPermissionDenied {
		t.Errorf("ErrPermission: got %q", got)
	}
	if got := classifyFilesystemError(fs.ErrNotExist); got != model.ErrorKindNotEnoughData {
		t.Errorf("ErrNotExist: got %q", got)
	}
	if got := classifyFilesystemError(errors.New("unknown")); got != model.ErrorKindNotEnoughData {
		t.Errorf("unknown error: got %q", got)
	}
}

func TestParseFirewallSummary(t *testing.T) {
	t.Parallel()

	result := model.CommandResult{ExitCode: 0, Stdout: "Status: active\nTo Action From\n"}
	summary, ok := parseFirewallSummary("ufw", result)
	if !ok {
		t.Fatal("expected ok=true for ufw")
	}
	if !summary.Enabled || summary.Source != "ufw" {
		t.Errorf("unexpected ufw summary: %+v", summary)
	}

	result = model.CommandResult{ExitCode: 0, Stdout: "running"}
	summary, ok = parseFirewallSummary("firewalld", result)
	if !ok || !summary.Enabled {
		t.Errorf("expected firewalld running, got ok=%v enabled=%v", ok, summary.Enabled)
	}

	result = model.CommandResult{ExitCode: 0, Stdout: "table inet filter { }"}
	summary, ok = parseFirewallSummary("nftables", result)
	if !ok || !summary.Enabled {
		t.Fatal("expected nftables enabled")
	}

	_, ok = parseFirewallSummary("unknown", model.CommandResult{ExitCode: 0, Stdout: "x"})
	if ok {
		t.Fatal("expected ok=false for unknown source")
	}

	_, ok = parseFirewallSummary("ufw", model.CommandResult{ExitCode: 1})
	if ok {
		t.Fatal("expected ok=false for non-zero exit")
	}

	result = model.CommandResult{ExitCode: 0, Stdout: "", Stderr: "inactive"}
	summary, ok = parseFirewallSummary("ufw", result)
	if !ok {
		t.Fatal("expected ok=true when falling back to stderr")
	}
	if summary.Enabled {
		t.Fatal("expected ufw disabled when output=inactive")
	}
}

func TestFirstOutputLine(t *testing.T) {
	t.Parallel()

	if got := firstOutputLine("first\nsecond\nthird"); got != "first" {
		t.Errorf("got %q, want first", got)
	}
	if got := firstOutputLine(""); got != "" {
		t.Errorf("got %q, want empty", got)
	}
	if got := firstOutputLine("  only  "); got != "only" {
		t.Errorf("got %q, want only", got)
	}
}

func TestMatchesDirectiveBoundary(t *testing.T) {
	t.Parallel()

	content := "server { listen 80; }"
	if !matchesDirectiveBoundary(content, 0, 6) {
		t.Error("expected true for 'server' at start")
	}
	if !matchesDirectiveBoundary(content, 9, 6) {
		t.Error("expected true for 'listen' as a word")
	}
	if matchesDirectiveBoundary("superserver { }", 5, 6) {
		t.Error("expected false for 'server' embedded in 'superserver'")
	}
}

func TestComposerRequirement(t *testing.T) {
	t.Parallel()

	manifest := composerManifest{
		Require:    map[string]string{"laravel/framework": "^11.0"},
		RequireDev: map[string]string{"phpunit/phpunit": "^10.0"},
	}

	if got := composerRequirement(manifest, "laravel/framework"); got != "^11.0" {
		t.Errorf("expected ^11.0, got %q", got)
	}
	if got := composerRequirement(manifest, "phpunit/phpunit"); got != "^10.0" {
		t.Errorf("expected ^10.0, got %q", got)
	}
	if got := composerRequirement(manifest, "missing/package"); got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

func TestSortCompactStringSlice(t *testing.T) {
	t.Parallel()

	result := sortCompactStringSlice([]string{"b", "a", "a", "c"})
	if len(result) != 3 || result[0] != "a" || result[1] != "b" || result[2] != "c" {
		t.Errorf("unexpected result: %v", result)
	}
}

func TestCollectEnvironmentInfo(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	envContent := "APP_DEBUG=true\nAPP_ENV=production\nAPP_KEY=base64:abc\nDB_PASSWORD=secret\nSESSION_SECURE_COOKIE=true\n"
	if err := os.WriteFile(dir+"/.env", []byte(envContent), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	service := newTestSnapshotService()
	info, unknowns := service.collectEnvironmentInfo(dir)
	if len(unknowns) != 0 {
		t.Fatalf("unexpected unknowns: %v", unknowns)
	}
	if !info.AppDebugDefined || info.AppDebugValue != "true" {
		t.Errorf("APP_DEBUG: defined=%v value=%q", info.AppDebugDefined, info.AppDebugValue)
	}
	if !info.DBPasswordDefined {
		t.Error("DB_PASSWORD should be defined")
	}
}

func TestCollectEnvironmentInfoMissing(t *testing.T) {
	t.Parallel()

	service := newTestSnapshotService()
	info, unknowns := service.collectEnvironmentInfo(t.TempDir())
	if len(unknowns) != 0 {
		t.Fatalf("unexpected unknowns for missing .env: %v", unknowns)
	}
	if info.AppDebugDefined {
		t.Error("nothing should be defined for missing .env")
	}
}

func TestCollectEnvironmentInfoUnreadable(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	if err := os.WriteFile(envPath, []byte("APP_DEBUG=true\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Chmod(envPath, 0o000); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(envPath, 0o644) })

	service := newTestSnapshotService()
	info, unknowns := service.collectEnvironmentInfo(dir)
	if info.AppDebugDefined {
		t.Fatal("unreadable .env should not populate environment info")
	}
	if len(unknowns) != 1 {
		t.Fatalf("expected one unknown for unreadable .env, got %d", len(unknowns))
	}
}

func TestReadOptionalFile(t *testing.T) {
	t.Parallel()

	service := newTestSnapshotService()

	data, unknown := service.readOptionalFile(t.TempDir()+"/missing.txt", "test")
	if data != nil || unknown != nil {
		t.Errorf("missing file: data=%v unknown=%v", data, unknown)
	}

	dir := t.TempDir()
	if err := os.WriteFile(dir+"/test.txt", []byte("hello"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	data, unknown = service.readOptionalFile(dir+"/test.txt", "test")
	if unknown != nil {
		t.Errorf("unexpected unknown: %v", unknown)
	}
	if string(data) != "hello" {
		t.Errorf("expected hello, got %q", data)
	}

	if err := os.Chmod(dir+"/test.txt", 0o000); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir+"/test.txt", 0o644) })
	_, unknown = service.readOptionalFile(dir+"/test.txt", "test")
	if unknown == nil {
		t.Fatal("expected unknown for unreadable file")
	}
}

func TestReadRequiredFile(t *testing.T) {
	t.Parallel()

	service := newTestSnapshotService()

	_, unknown, ok := service.readRequiredFile(t.TempDir()+"/missing.txt", "test")
	if ok || unknown == nil {
		t.Error("expected failure for missing required file")
	}

	dir := t.TempDir()
	if err := os.WriteFile(dir+"/test.txt", []byte("content"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	data, unknown, ok := service.readRequiredFile(dir+"/test.txt", "test")
	if !ok || unknown != nil {
		t.Error("expected success for existing file")
	}
	if string(data) != "content" {
		t.Errorf("expected content, got %q", data)
	}
}

func TestParseSupervisorSectionHeader(t *testing.T) {
	t.Parallel()

	cases := []struct {
		line     string
		wantPgm  bool
		wantHTTP bool
		wantErr  bool
	}{
		{"[program:laravel-worker]", true, false, false},
		{"[inet_http_server]", false, true, false},
		{"[unix_http_server]", false, false, false},
		{"[supervisord]", false, false, false},
		{"[supervisorctl]", false, false, false},
	}

	for _, tc := range cases {
		_, pgm, http, err := parseSupervisorSectionHeader("/etc/supervisor/conf.d/test.conf", tc.line)
		if (err != nil) != tc.wantErr {
			t.Errorf("parseSupervisorSectionHeader(%q) err=%v, wantErr=%v", tc.line, err, tc.wantErr)
		}
		if (pgm != nil) != tc.wantPgm {
			t.Errorf("parseSupervisorSectionHeader(%q) pgm=%v, wantPgm=%v", tc.line, pgm != nil, tc.wantPgm)
		}
		if (http != nil) != tc.wantHTTP {
			t.Errorf("parseSupervisorSectionHeader(%q) http=%v, wantHTTP=%v", tc.line, http != nil, tc.wantHTTP)
		}
	}
}

func compilePattern(pattern string) *regexp.Regexp {
	return regexp.MustCompile(pattern)
}
