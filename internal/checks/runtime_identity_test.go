package checks

import (
	"testing"

	"github.com/nagi1/larainspect/internal/model"
)

func TestCollectAppRuntimeIdentitiesIncludesMatchedPoolsAndWorkerUsers(t *testing.T) {
	t.Parallel()

	app := model.LaravelApp{RootPath: "/var/www/shop"}
	snapshot := model.Snapshot{
		Apps: []model.LaravelApp{app},
		NginxSites: []model.NginxSite{{
			ConfigPath:         "/etc/nginx/sites-enabled/shop.conf",
			Root:               "/var/www/shop/public",
			FastCGIPassTargets: []string{"unix:/run/php/shop.sock"},
		}},
		PHPFPMPools: []model.PHPFPMPool{{
			ConfigPath: "/etc/php/8.3/fpm/pool.d/shop.conf",
			Name:       "shop",
			User:       "www-data",
			Group:      "www-data",
			Listen:     "/run/php/shop.sock",
		}},
		SystemdUnits: []model.SystemdUnit{{
			Path:             "/etc/systemd/system/laravel-worker.service",
			Name:             "laravel-worker.service",
			User:             "deploy",
			WorkingDirectory: "/var/www/shop",
			ExecStart:        "/usr/bin/php artisan queue:work",
		}},
	}

	identities := collectAppRuntimeIdentities(app, snapshot, model.AuditConfig{})
	if len(identities.Pools) != 1 {
		t.Fatalf("collectAppRuntimeIdentities() pools = %+v", identities.Pools)
	}
	if !containsString(identities.Users, "www-data") || !containsString(identities.Users, "deploy") {
		t.Fatalf("collectAppRuntimeIdentities() users = %+v", identities.Users)
	}
	if !containsString(identities.Groups, "www-data") {
		t.Fatalf("collectAppRuntimeIdentities() groups = %+v", identities.Groups)
	}
}

func TestCollectAppRuntimeIdentitiesIncludesConfiguredRuntimePolicy(t *testing.T) {
	t.Parallel()

	identities := collectAppRuntimeIdentities(model.LaravelApp{RootPath: "/var/www/shop"}, model.Snapshot{}, model.AuditConfig{
		Identities: model.IdentityConfig{
			RuntimeUsers:  []string{"php-shop"},
			RuntimeGroups: []string{"php-shop"},
		},
	})

	if !containsString(identities.Users, "php-shop") {
		t.Fatalf("expected configured runtime user, got %+v", identities.Users)
	}
	if !containsString(identities.Groups, "php-shop") {
		t.Fatalf("expected configured runtime group, got %+v", identities.Groups)
	}
}

func TestPathWritableByRuntimeIdentityUsesOwnerGroupAndWorldBits(t *testing.T) {
	t.Parallel()

	identities := appRuntimeIdentities{
		Users:  []string{"www-data"},
		Groups: []string{"www-data"},
	}

	tests := []struct {
		name       string
		pathRecord model.PathRecord
		want       bool
	}{
		{
			name: "owner writable",
			pathRecord: model.PathRecord{
				Inspected:   true,
				Exists:      true,
				Permissions: 0o640,
				OwnerName:   "www-data",
			},
			want: true,
		},
		{
			name: "group writable",
			pathRecord: model.PathRecord{
				Inspected:   true,
				Exists:      true,
				Permissions: 0o660,
				GroupName:   "www-data",
			},
			want: true,
		},
		{
			name: "world writable",
			pathRecord: model.PathRecord{
				Inspected:   true,
				Exists:      true,
				Permissions: 0o606,
			},
			want: true,
		},
		{
			name: "not writable",
			pathRecord: model.PathRecord{
				Inspected:   true,
				Exists:      true,
				Permissions: 0o640,
				OwnerName:   "deploy",
				GroupName:   "deploy",
			},
			want: false,
		},
	}

	for _, test := range tests {
		if got := pathWritableByRuntimeIdentity(test.pathRecord, identities); got != test.want {
			t.Fatalf("%s: pathWritableByRuntimeIdentity() = %v", test.name, got)
		}
	}
}
