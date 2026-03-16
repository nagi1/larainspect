package phpconfig

import (
	"testing"

	"github.com/nagi1/larainspect/internal/model"
)

func TestParsePoolsParsesSecurityExtensionsAndCGIOverride(t *testing.T) {
	t.Parallel()

	pools, err := ParsePools("/etc/php/8.3/fpm/pool.d/shop.conf", `
[shop]
user = app
group = app
listen = /run/php/shop.sock
security.limit_extensions = .php .phar .phtml
php_admin_value[cgi.fix_pathinfo] = 1
`)
	if err != nil {
		t.Fatalf("ParsePools() error = %v", err)
	}
	if len(pools) != 1 {
		t.Fatalf("expected 1 pool, got %+v", pools)
	}
	if pools[0].CGIFixPathinfo != "1" {
		t.Fatalf("expected cgi.fix_pathinfo override, got %+v", pools[0])
	}
	if len(pools[0].SecurityLimitExtensions) != 3 {
		t.Fatalf("expected security.limit_extensions to be parsed, got %+v", pools[0].SecurityLimitExtensions)
	}
}

func TestParseRuntimeINIParsesRelevantPHPFlags(t *testing.T) {
	t.Parallel()

	runtimeConfig, err := ParseRuntimeINI("/etc/php/8.3/fpm/php.ini", `
[PHP]
cgi.fix_pathinfo = 0
expose_php = Off
`)
	if err != nil {
		t.Fatalf("ParseRuntimeINI() error = %v", err)
	}
	if runtimeConfig.CGIFixPathinfo != "0" || runtimeConfig.ExposePHP != "Off" {
		t.Fatalf("unexpected parsed php.ini config: %+v", runtimeConfig)
	}
}

func TestParsePoolsCleansQuotedExtensionsAndPHPValueOverride(t *testing.T) {
	t.Parallel()

	pools, err := ParsePools("/etc/php-fpm.d/www.conf", `
[www]
security.limit_extensions = ".php, .phar"
php_value[cgi.fix_pathinfo] = '0'
`)
	if err != nil {
		t.Fatalf("ParsePools() error = %v", err)
	}
	if len(pools) != 1 {
		t.Fatalf("expected 1 pool, got %+v", pools)
	}
	if pools[0].CGIFixPathinfo != "0" {
		t.Fatalf("expected php_value override, got %+v", pools[0])
	}
	if len(pools[0].SecurityLimitExtensions) != 2 || pools[0].SecurityLimitExtensions[0] != ".phar" || pools[0].SecurityLimitExtensions[1] != ".php" {
		t.Fatalf("expected normalized extensions, got %+v", pools[0].SecurityLimitExtensions)
	}
}

func TestParseRuntimeINIParsesDefaultSectionValues(t *testing.T) {
	t.Parallel()

	runtimeConfig, err := ParseRuntimeINI("/etc/php.ini", "cgi.fix_pathinfo = 1\n")
	if err != nil {
		t.Fatalf("ParseRuntimeINI() error = %v", err)
	}
	if runtimeConfig.CGIFixPathinfo != "1" {
		t.Fatalf("expected default-section cgi.fix_pathinfo, got %+v", runtimeConfig)
	}
}

func TestDirectiveTargetsPHPValueRecognizesSupportedPrefixes(t *testing.T) {
	t.Parallel()

	if !directiveTargetsPHPValue("php_admin_value[cgi.fix_pathinfo]", "cgi.fix_pathinfo") {
		t.Fatal("expected php_admin_value key to match")
	}
	if !directiveTargetsPHPValue("php_value[cgi.fix_pathinfo]", "cgi.fix_pathinfo") {
		t.Fatal("expected php_value key to match")
	}
	if directiveTargetsPHPValue("env[cgi.fix_pathinfo]", "cgi.fix_pathinfo") {
		t.Fatal("expected unrelated key to be rejected")
	}
}

func TestCleanValueStripsQuotesAndWhitespace(t *testing.T) {
	t.Parallel()

	if got := cleanValue(` "value" `); got != "value" {
		t.Fatalf("cleanValue() = %q, want value", got)
	}
	if got := cleanValue(" 'value' "); got != "value" {
		t.Fatalf("cleanValue() single quotes = %q, want value", got)
	}
	if got := cleanValue(" raw "); got != "raw" {
		t.Fatalf("cleanValue() raw = %q, want raw", got)
	}
}

func TestParseLimitExtensionsNormalizesDifferentSeparators(t *testing.T) {
	t.Parallel()

	got := parseLimitExtensions(".php,.phar\n phtml")
	if len(got) != 3 {
		t.Fatalf("parseLimitExtensions() = %+v", got)
	}
	if got[0] != ".php" || got[1] != ".phar" || got[2] != ".phtml" {
		t.Fatalf("parseLimitExtensions() normalized = %+v", got)
	}
}

func TestApplyPoolDirectiveNormalizesAndSortsExtensions(t *testing.T) {
	t.Parallel()

	pool := model.PHPFPMPool{}
	applyPoolDirective(&pool, "security.limit_extensions", ".phar .php .phar")
	normalizePool(&pool)

	if len(pool.SecurityLimitExtensions) != 2 {
		t.Fatalf("expected deduped extensions, got %+v", pool.SecurityLimitExtensions)
	}
	if pool.SecurityLimitExtensions[0] != ".phar" || pool.SecurityLimitExtensions[1] != ".php" {
		t.Fatalf("expected sorted extensions, got %+v", pool.SecurityLimitExtensions)
	}
}

func TestApplyPoolDirectiveCoversStandardFields(t *testing.T) {
	t.Parallel()

	pool := model.PHPFPMPool{}
	applyPoolDirective(&pool, "user", "app")
	applyPoolDirective(&pool, "group", "app")
	applyPoolDirective(&pool, "listen", "/run/php/app.sock")
	applyPoolDirective(&pool, "listen.owner", "www-data")
	applyPoolDirective(&pool, "listen.group", "www-data")
	applyPoolDirective(&pool, "listen.mode", "0660")
	applyPoolDirective(&pool, "clear_env", "no")

	if pool.User != "app" || pool.Group != "app" || pool.Listen != "/run/php/app.sock" || pool.ListenOwner != "www-data" || pool.ListenGroup != "www-data" || pool.ListenMode != "0660" || pool.ClearEnv != "no" {
		t.Fatalf("unexpected pool after directive application: %+v", pool)
	}
}

func TestNormalizePoolHandlesEmptyExtensionList(t *testing.T) {
	t.Parallel()

	pool := model.PHPFPMPool{}
	normalizePool(&pool)
	if pool.SecurityLimitExtensions != nil {
		t.Fatalf("expected nil extension list to remain nil, got %+v", pool.SecurityLimitExtensions)
	}
}

func TestParseRuntimeINIRejectsInvalidConfig(t *testing.T) {
	t.Parallel()

	if _, err := ParseRuntimeINI("/etc/php.ini", "["); err == nil {
		t.Fatal("expected invalid php.ini to return an error")
	}
}
