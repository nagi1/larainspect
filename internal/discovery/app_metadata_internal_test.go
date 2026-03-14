package discovery

import (
	"errors"
	"io/fs"
	"testing"
)

func TestLookupPrincipalNameHandlesResolverOutcomes(t *testing.T) {
	t.Parallel()

	service := newTestSnapshotService()
	if got := service.lookupPrincipalName(1000, func(value string) (string, error) {
		if value != "1000" {
			t.Fatalf("resolver received %q", value)
		}
		return "www-data", nil
	}); got != "www-data" {
		t.Fatalf("lookupPrincipalName() = %q", got)
	}

	if got := service.lookupPrincipalName(1000, func(string) (string, error) {
		return "", errors.New("missing")
	}); got != "" {
		t.Fatalf("lookupPrincipalName() error path = %q", got)
	}

	service.lookupUserName = nil
	if got := service.lookupPrincipalName(1000, nil); got != "" {
		t.Fatalf("lookupPrincipalName() nil resolver = %q", got)
	}
}

func TestIsExpectedWritablePHPPath(t *testing.T) {
	t.Parallel()

	cases := []struct {
		path string
		want bool
	}{
		{"bootstrap/cache/config.php", true},
		{"bootstrap/cache/packages.php", true},
		{"bootstrap/cache/services.php", true},
		{"bootstrap/cache/routes.php", true},
		{"bootstrap/cache/routes-v7.php", true},
		{"storage/framework/views/abc123def.php", true},
		{"app/Http/Controllers/HomeController.php", false},
		{"config/app.php", false},
		{"bootstrap/cache/readme.txt", false},
		{"storage/logs/laravel.log", false},
	}

	for _, tc := range cases {
		if got := isExpectedWritablePHPPath(tc.path); got != tc.want {
			t.Errorf("isExpectedWritablePHPPath(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestParseEnvironmentInfoAllFields(t *testing.T) {
	t.Parallel()

	env := []byte(`APP_DEBUG=true
APP_ENV=production
APP_KEY=base64:dGVzdA==
DB_PASSWORD=secret
SESSION_SECURE_COOKIE=true
# comment line
UNRELATED=value

export MAIL_HOST=smtp.example.com
`)

	info := parseEnvironmentInfo(env)

	if !info.AppDebugDefined || info.AppDebugValue != "true" {
		t.Errorf("APP_DEBUG: defined=%v value=%q", info.AppDebugDefined, info.AppDebugValue)
	}
	if !info.AppEnvDefined || info.AppEnvValue != "production" {
		t.Errorf("APP_ENV: defined=%v value=%q", info.AppEnvDefined, info.AppEnvValue)
	}
	if !info.AppKeyDefined || info.AppKeyValue != "base64:dGVzdA==" {
		t.Errorf("APP_KEY: defined=%v value=%q", info.AppKeyDefined, info.AppKeyValue)
	}
	if !info.DBPasswordDefined || info.DBPasswordEmpty {
		t.Errorf("DB_PASSWORD: defined=%v empty=%v", info.DBPasswordDefined, info.DBPasswordEmpty)
	}
	if !info.SessionSecureCookieDefined || info.SessionSecureCookieValue != "true" {
		t.Errorf("SESSION_SECURE_COOKIE: defined=%v value=%q", info.SessionSecureCookieDefined, info.SessionSecureCookieValue)
	}
}

func TestParseEnvironmentInfoDBPasswordEmpty(t *testing.T) {
	t.Parallel()

	info := parseEnvironmentInfo([]byte("DB_PASSWORD=\n"))
	if !info.DBPasswordDefined {
		t.Fatal("DB_PASSWORD should be defined")
	}
	if !info.DBPasswordEmpty {
		t.Fatal("DB_PASSWORD should be empty")
	}
}

func TestNormalizeEnvironmentValue(t *testing.T) {
	t.Parallel()

	cases := []struct {
		input string
		want  string
	}{
		{`"quoted"`, "quoted"},
		{`'single'`, "single"},
		{`plain`, "plain"},
		{`value # inline comment`, "value"},
		{`  spaces  `, "spaces"},
	}

	for _, tc := range cases {
		if got := normalizeEnvironmentValue(tc.input); got != tc.want {
			t.Errorf("normalizeEnvironmentValue(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestAppendSourceMatchIfContainsAll(t *testing.T) {
	t.Parallel()

	content := "use Illuminate\\Encryption\\Encrypter;\nreturn $encrypter->decrypt($value);"

	// All required substrings present, with anchor match.
	matches := appendSourceMatchIfContainsAll(
		nil, "routes/web.php", content,
		"test.rule", "custom encryption usage",
		[]string{"Encrypter", "decrypt"},
		[]string{"decrypt"},
	)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].Line != 2 {
		t.Fatalf("expected line 2, got %d", matches[0].Line)
	}

	// Missing a required substring.
	matches = appendSourceMatchIfContainsAll(
		nil, "routes/web.php", content,
		"test.rule", "detail",
		[]string{"Encrypter", "MISSING"},
		[]string{"decrypt"},
	)
	if len(matches) != 0 {
		t.Fatal("expected 0 matches when a required substring is missing")
	}

	// No anchor substrings — should default to line 1.
	matches = appendSourceMatchIfContainsAll(
		nil, "routes/web.php", content,
		"test.rule", "detail",
		[]string{"Encrypter"},
		nil,
	)
	if len(matches) != 1 || matches[0].Line != 1 {
		t.Fatalf("expected line 1 when no anchors, got %d matches line=%d", len(matches), func() int {
			if len(matches) > 0 {
				return matches[0].Line
			}
			return -1
		}())
	}
}

func TestLineNumberForOffset(t *testing.T) {
	t.Parallel()

	content := "line1\nline2\nline3"
	if got := lineNumberForOffset(content, 0); got != 1 {
		t.Errorf("offset 0: got %d, want 1", got)
	}
	if got := lineNumberForOffset(content, 6); got != 2 {
		t.Errorf("offset 6: got %d, want 2", got)
	}
	if got := lineNumberForOffset(content, -1); got != 1 {
		t.Errorf("negative offset: got %d, want 1", got)
	}
}

func TestAppendSourceMatchIfLineMatchesRegexWithoutSubstrings(t *testing.T) {
	t.Parallel()

	content := "normal line\neval($code);\nsafe line"
	pattern := compilePattern(`eval\(`)

	// No forbidden substrings — should match.
	matches := appendSourceMatchIfLineMatchesRegexWithoutSubstrings(
		nil, "app.php", content,
		"test.eval", "eval usage",
		pattern, nil,
	)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].Line != 2 {
		t.Fatalf("expected line 2, got %d", matches[0].Line)
	}

	// With forbidden substring present — should not match.
	matches = appendSourceMatchIfLineMatchesRegexWithoutSubstrings(
		nil, "app.php", content,
		"test.eval", "eval usage",
		pattern, []string{"$code"},
	)
	if len(matches) != 0 {
		t.Fatal("expected 0 matches when forbidden substring present on matched line")
	}
}

func TestMatchesPublicAdminToolPath(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		isDir   bool
		want    bool
	}{
		{"adminer.php", false, true},
		{"adminer-4.8.1.php", false, true},
		{"phpinfo.php", false, true},
		{"phpinfo-check.php", false, true},
		{"phpmyadmin", true, true},
		{"phpmyadmin", false, true},
		{"index.php", false, false},
		{"admin", true, false},
	}

	for _, tc := range cases {
		entry := fakeDirEntry{name: tc.name, dir: tc.isDir}
		if got := matchesPublicAdminToolPath(tc.name, entry); got != tc.want {
			t.Errorf("matchesPublicAdminToolPath(%q, isDir=%v) = %v, want %v", tc.name, tc.isDir, got, tc.want)
		}
	}
}

type fakeDirEntry struct {
	name string
	dir  bool
}

func (f fakeDirEntry) Name() string              { return f.name }
func (f fakeDirEntry) IsDir() bool               { return f.dir }
func (f fakeDirEntry) Type() fs.FileMode         { return 0 }
func (f fakeDirEntry) Info() (fs.FileInfo, error) { return nil, nil }
