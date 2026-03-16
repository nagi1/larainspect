package discovery

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	crossplane "github.com/nginxinc/nginx-go-crossplane"
)

func TestParseNginxSitesParsesRelevantLaravelSignals(t *testing.T) {
	t.Parallel()

	sites, err := parseNginxSites("/etc/nginx/sites-enabled/shop.conf", `
server {
    server_name shop.test;
    root /var/www/shop/public;
    index index.php index.html;

    location = /index.php {
        fastcgi_pass unix:/run/php/shop.sock;
    }

    location ~ \.php$ {
        fastcgi_pass unix:/run/php/shop.sock;
    }

    location ~ /\.(?!well-known).* {
        deny all;
    }

    location ~* \.(env|sql|zip)$ {
        return 404;
    }

    location ~ ^/uploads/.*\.php$ {
        fastcgi_pass unix:/run/php/shop.sock;
    }
}
`)
	if err != nil {
		t.Fatalf("parseNginxSites() error = %v", err)
	}

	if len(sites) != 1 {
		t.Fatalf("expected 1 site, got %+v", sites)
	}

	site := sites[0]
	if !site.HasGenericPHPLocation || !site.HasFrontControllerOnly || !site.HiddenFilesDenied || !site.SensitiveFilesDenied || !site.UploadExecutionAllowed {
		t.Fatalf("expected parsed nginx protections and execution signals, got %+v", site)
	}

	if len(site.FastCGIPassTargets) != 1 || site.FastCGIPassTargets[0] != "unix:/run/php/shop.sock" {
		t.Fatalf("unexpected fastcgi_pass targets: %+v", site.FastCGIPassTargets)
	}
}

func TestParseNginxSitesRecognizesAlternateExecutablePHPExtensions(t *testing.T) {
	t.Parallel()

	sites, err := parseNginxSites("/etc/nginx/sites-enabled/shop.conf", `
server {
    root /var/www/shop/public;

    location = /index.php {
        fastcgi_pass unix:/run/php/shop.sock;
    }

    location ~* \.(php|phtml|phar)$ {
        fastcgi_pass unix:/run/php/shop.sock;
    }

    location ~ ^/uploads/.*\.(phtml|phar)$ {
        fastcgi_pass unix:/run/php/shop.sock;
    }
}
`)
	if err != nil {
		t.Fatalf("parseNginxSites() error = %v", err)
	}
	if len(sites) != 1 {
		t.Fatalf("expected 1 site, got %+v", sites)
	}

	site := sites[0]
	if !site.HasGenericPHPLocation {
		t.Fatalf("expected alternate executable php extensions to count as generic php handling, got %+v", site)
	}
	if !site.UploadExecutionAllowed {
		t.Fatalf("expected upload-adjacent alternate php extensions to count as upload execution, got %+v", site)
	}
}

func TestParseNginxSitesDoesNotTreatDenyRuleAsPHPExecution(t *testing.T) {
	t.Parallel()

	sites, err := parseNginxSites("/etc/nginx/sites-enabled/shop.conf", `
server {
    root /var/www/shop/public;

    location ~ ^/\.well-known/.*\.(?:php|phtml|phar|jsp|py|pl|cgi|sh|bash|lua|js|css|ts|go|zip|tar|gz|rar|7z|sql|bak)$ {
        return 403;
    }

    location = /index.php {
        fastcgi_pass unix:/run/php/shop.sock;
    }

    location ~ [^/]\.php(/|$) {
        try_files $uri =404;
        fastcgi_pass unix:/run/php/shop.sock;
    }
}
`)
	if err != nil {
		t.Fatalf("parseNginxSites() error = %v", err)
	}
	if len(sites) != 1 {
		t.Fatalf("expected 1 site, got %+v", sites)
	}

	site := sites[0]
	if !site.HasGenericPHPLocation {
		t.Fatalf("expected generic php execution matcher, got %+v", site)
	}
	for _, matcher := range site.GenericPHPLocations {
		if strings.Contains(matcher, "/\\.well-known/") {
			t.Fatalf("expected deny matcher to be excluded from generic php execution evidence, got %+v", site.GenericPHPLocations)
		}
	}
	if !site.SensitiveFilesDenied {
		t.Fatalf("expected deny matcher to still count as sensitive file deny, got %+v", site)
	}
}

func TestParseNginxSitesRejectsUnbalancedConfig(t *testing.T) {
	t.Parallel()

	if _, err := parseNginxSites("/etc/nginx/nginx.conf", "server {"); err == nil {
		t.Fatal("expected nginx parse error for unbalanced braces")
	}
}

func TestParseNginxDumpSplitsMultipleSections(t *testing.T) {
	t.Parallel()

	dump := `nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
nginx: configuration file /etc/nginx/nginx.conf test is successful
# configuration file /etc/nginx/nginx.conf:
http {
    include /etc/nginx/sites-enabled/*;
}
# configuration file /etc/nginx/sites-enabled/app.conf:
server {
    server_name app.example.com;
    root /var/www/app/public;
    location ~ \.php$ {
        fastcgi_pass unix:/run/php/app.sock;
    }
}
# configuration file /etc/nginx/sites-enabled/api.conf:
server {
    server_name api.example.com;
    root /var/www/api/public;
    location = /index.php {
        fastcgi_pass unix:/run/php/api.sock;
    }
}
`
	sites, err := parseNginxDump(dump)
	if err != nil {
		t.Fatalf("parseNginxDump() error = %v", err)
	}

	if len(sites) != 2 {
		t.Fatalf("expected 2 sites from nginx -T dump, got %d: %+v", len(sites), sites)
	}
}

func TestParseNginxDumpHandlesPlainConfigWithNoMarkers(t *testing.T) {
	t.Parallel()

	sites, err := parseNginxDump(`server { root /var/www/app/public; location ~ \.php$ { fastcgi_pass unix:/run/php/app.sock; } }`)
	if err != nil {
		t.Fatalf("parseNginxDump() error = %v", err)
	}
	if len(sites) != 1 {
		t.Fatalf("expected 1 site from plain config, got %d", len(sites))
	}
}

func TestParseNginxDumpRejectsBrokenSectionWhenOthersAreValid(t *testing.T) {
	t.Parallel()

	_, err := parseNginxDump(`nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
# configuration file /etc/nginx/sites-enabled/app.conf:
server {
    root /var/www/app/public;
    location ~ \.php$ {
        fastcgi_pass unix:/run/php/app.sock;
    }
}
# configuration file /etc/nginx/sites-enabled/broken.conf:
server {
`)
	if err == nil {
		t.Fatal("expected nginx -T parsing to fail when any section is invalid")
	}
	if !strings.Contains(err.Error(), "/etc/nginx/sites-enabled/broken.conf") {
		t.Fatalf("expected error to identify broken section, got %v", err)
	}
}

func TestParseNginxSitesHandlesQuotedDirectives(t *testing.T) {
	t.Parallel()

	sites, err := parseNginxSites("/etc/nginx/test.conf", `
server {
    server_name "example.com";
    root "/var/www/app/public";
    location ~ \.php$ {
        fastcgi_pass unix:/run/php/app.sock;
    }
}
`)
	if err != nil {
		t.Fatalf("parseNginxSites() error = %v", err)
	}
	if len(sites) != 1 {
		t.Fatalf("expected 1 site, got %+v", sites)
	}
	if sites[0].Root != "/var/www/app/public" {
		t.Fatalf("expected unquoted root, got %q", sites[0].Root)
	}
	if len(sites[0].ServerNames) != 1 || sites[0].ServerNames[0] != "example.com" {
		t.Fatalf("expected unquoted server_name, got %+v", sites[0].ServerNames)
	}
}

func TestParseNginxSitesHandlesHttpWrappedServerBlocks(t *testing.T) {
	t.Parallel()

	sites, err := parseNginxSites("/etc/nginx/nginx.conf", `
http {
    server {
        server_name inner.test;
        root /var/www/inner/public;
    }
}
`)
	if err != nil {
		t.Fatalf("parseNginxSites() error = %v", err)
	}
	if len(sites) != 1 {
		t.Fatalf("expected 1 site from http-wrapped config, got %d", len(sites))
	}
	if sites[0].Root != "/var/www/inner/public" {
		t.Fatalf("expected root from http-wrapped server, got %q", sites[0].Root)
	}
}

func TestParseNginxSitesResolvingFollowsIncludes(t *testing.T) {
	t.Parallel()

	mainConfig := `server {
    root /var/www/app/public;
    include /etc/nginx/snippets/php.conf;
}`
	snippetConfig := []byte(`location ~ \.php$ {
    fastcgi_pass unix:/run/php/app.sock;
}`)

	readFile := func(path string) ([]byte, error) {
		if path == "/etc/nginx/snippets/php.conf" {
			return snippetConfig, nil
		}
		return nil, fmt.Errorf("file not found: %s", path)
	}
	globPaths := func(pattern string) ([]string, error) {
		return nil, nil
	}

	sites, err := parseNginxSitesResolving("/etc/nginx/sites-enabled/app.conf", []byte(mainConfig), readFile, globPaths)
	if err != nil {
		t.Fatalf("parseNginxSitesResolving() error = %v", err)
	}
	if len(sites) != 1 {
		t.Fatalf("expected 1 site with resolved includes, got %d", len(sites))
	}
	if !sites[0].HasGenericPHPLocation {
		t.Fatalf("expected generic PHP location from included snippet, got %+v", sites[0])
	}
}

func TestFirstNginxPayloadErrorPrefersPayloadError(t *testing.T) {
	t.Parallel()

	err := firstNginxPayloadError(&crossplane.Payload{
		Errors: []crossplane.PayloadError{{
			File:  "/etc/nginx/nginx.conf",
			Error: errors.New("unexpected '}'"),
		}},
	})
	if err == nil {
		t.Fatal("expected payload error to be returned")
	}
	if !strings.Contains(err.Error(), "/etc/nginx/nginx.conf") {
		t.Fatalf("expected file path in payload error, got %v", err)
	}
}

func TestFirstNginxPayloadErrorFallsBackToConfigError(t *testing.T) {
	t.Parallel()

	err := firstNginxPayloadError(&crossplane.Payload{
		Config: []crossplane.Config{{
			File:   "/etc/nginx/sites-enabled/app.conf",
			Errors: []crossplane.ConfigError{{Error: errors.New("invalid number of arguments")}},
		}},
	})
	if err == nil {
		t.Fatal("expected config error to be returned")
	}
	if !strings.Contains(err.Error(), "/etc/nginx/sites-enabled/app.conf") {
		t.Fatalf("expected file path in config error, got %v", err)
	}
}

func TestFirstNginxPayloadErrorReturnsNilWhenClean(t *testing.T) {
	t.Parallel()

	if err := firstNginxPayloadError(&crossplane.Payload{}); err != nil {
		t.Fatalf("expected nil error for clean payload, got %v", err)
	}
}
