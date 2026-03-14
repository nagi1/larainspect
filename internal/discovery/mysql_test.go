package discovery

import "testing"

func TestParseMySQLConfigsParsesRelevantSections(t *testing.T) {
	t.Parallel()

	configs, err := parseMySQLConfigs("/etc/my.cnf", `
[mysqld]
bind-address = 127.0.0.1
port = 3306
socket = /var/lib/mysql/mysql.sock
datadir = /www/server/data
skip-networking

[client]
socket = /var/lib/mysql/mysql.sock
`)
	if err != nil {
		t.Fatalf("parseMySQLConfigs() error = %v", err)
	}
	if len(configs) != 2 {
		t.Fatalf("expected 2 mysql config sections, got %+v", configs)
	}
	if configs[0].Section != "client" || configs[1].Section != "mysqld" {
		t.Fatalf("expected sorted mysql sections, got %+v", configs)
	}
	if configs[1].BindAddress != "127.0.0.1" || configs[1].DataDir != "/www/server/data" || !configs[1].SkipNetworking {
		t.Fatalf("unexpected mysqld config %+v", configs[1])
	}
	if configs[0].Socket != "/var/lib/mysql/mysql.sock" {
		t.Fatalf("unexpected client socket %+v", configs[0])
	}
}

func TestParseMySQLConfigsRejectsMalformedSection(t *testing.T) {
	t.Parallel()

	if _, err := parseMySQLConfigs("/etc/my.cnf", "[mysqld\nbind-address=127.0.0.1"); err == nil {
		t.Fatal("expected malformed mysql section error")
	}
}
