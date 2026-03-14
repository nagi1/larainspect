package checks

import (
	"context"
	"strings"

	"github.com/nagi1/larainspect/internal/model"
)

const operationalNetworkCheckID = "operations.network"

var _ Check = OperationalNetworkCheck{}

type OperationalNetworkCheck struct{}

func init() {
	MustRegister(OperationalNetworkCheck{})
}

func (OperationalNetworkCheck) ID() string {
	return operationalNetworkCheckID
}

func (OperationalNetworkCheck) Description() string {
	return "Inspect exposed listeners and network surfaces around Laravel services."
}

func (OperationalNetworkCheck) Run(_ context.Context, execution model.ExecutionContext, snapshot model.Snapshot) (model.CheckResult, error) {
	if execution.Config.Scope != model.ScanScopeHost && len(snapshot.Apps) == 0 {
		return model.CheckResult{}, nil
	}

	findings := []model.Finding{}

	for _, listener := range snapshot.Listeners {
		if !isBroadListenerAddress(listener.LocalAddress) || isLoopbackListenerAddress(listener.LocalAddress) {
			continue
		}

		switch {
		case listenerHasAnyProcessName(listener, "redis-server") || listener.LocalPort == "6379":
			findings = append(findings, buildBroadListenerFinding(listener, "Redis is reachable on all network interfaces", "A broadly exposed Redis service can hand sessions, queues, and cached secrets to unintended systems or attackers on the network.", "Bind Redis to loopback or a tightly scoped private address and restrict access with firewall or network controls."))
		case listenerHasAnyProcessName(listener, "mysqld", "mariadbd") || listener.LocalPort == "3306":
			findings = append(findings, buildBroadListenerFinding(listener, "MySQL is reachable on all network interfaces", "A broadly exposed MySQL service turns weak passwords, leaked credentials, or overly broad grants into remote database access.", "Restrict MySQL to loopback or an explicitly trusted internal address and keep public exposure behind intentional controls only."))
		case listenerHasAnyProcessName(listener, "postgres") || listener.LocalPort == "5432":
			findings = append(findings, buildBroadListenerFinding(listener, "Postgres is reachable on all network interfaces", "A broadly exposed Postgres service is easier to probe remotely and makes leaked database credentials more dangerous.", "Bind Postgres to loopback or a tightly scoped private address and review host-based access rules."))
		case listenerHasAnyProcessName(listener, "php-fpm", "php-fpm8.3", "php-fpm8.2") || listener.LocalPort == "9000":
			findings = append(findings, buildBroadListenerFinding(listener, "PHP-FPM is reachable on a network port outside the local host", "A broadly reachable PHP-FPM port exposes the PHP runtime directly instead of keeping it behind the local web server.", "Prefer a Unix socket for local integration or restrict PHP-FPM TCP listeners to loopback or a tightly controlled private address."))
		case listenerHasAnyProcessName(listener, "php") && (listener.LocalPort == "8000" || listener.LocalPort == "8080"):
			findings = append(findings, buildBroadListenerFinding(listener, "A likely development server is reachable on all network interfaces", "An accidental development server bypasses the normal Nginx and PHP-FPM boundary and may expose debug behavior or incomplete routing rules.", "Shut down the development server and serve Laravel only through the intended production web stack."))
		case (listener.LocalPort == "6001" || listener.LocalPort == "6002") && (listenerHasAnyProcessName(listener, "node", "php") || len(listener.ProcessNames) == 0):
			findings = append(findings, buildBroadListenerFinding(listener, "A realtime or websocket service is reachable on all network interfaces", "A broadly exposed realtime service increases the public attack surface around the app when it is not intentionally scoped behind the expected proxy and auth boundary.", "Bind realtime services to the intended interface only and confirm they sit behind the expected reverse proxy and authentication boundary."))
		}
	}

	for _, server := range snapshot.SupervisorHTTPServers {
		if !isBroadSupervisorBind(server.Bind) {
			continue
		}

		findings = append(findings, buildSupervisorHTTPExposureFinding(server))
	}

	return model.CheckResult{Findings: findings}, nil
}

func buildBroadListenerFinding(listener model.ListenerRecord, title string, why string, remediation string) model.Finding {
	evidence := []model.Evidence{
		{Label: "protocol", Detail: listener.Protocol},
		{Label: "address", Detail: listener.LocalAddress},
		{Label: "port", Detail: listener.LocalPort},
	}
	if len(listener.ProcessNames) > 0 {
		evidence = append(evidence, model.Evidence{Label: "processes", Detail: strings.Join(listener.ProcessNames, ", ")})
	}

	return model.Finding{
		ID:          buildFindingID(operationalNetworkCheckID, "broad_listener", listener.LocalAddress+"."+listener.LocalPort),
		CheckID:     operationalNetworkCheckID,
		Class:       model.FindingClassDirect,
		Severity:    model.SeverityHigh,
		Confidence:  model.ConfidenceConfirmed,
		Title:       title,
		Why:         why,
		Remediation: remediation,
		Evidence:    evidence,
		Affected: []model.Target{
			{Type: "value", Value: listener.LocalAddress + ":" + listener.LocalPort},
		},
	}
}

func buildSupervisorHTTPExposureFinding(server model.SupervisorHTTPServer) model.Finding {
	severity := model.SeverityHigh
	why := "Supervisor's web control panel can start, stop, and manage processes, so it should stay on loopback or another tightly scoped management address."
	remediation := "Bind Supervisor inet_http_server to 127.0.0.1 only or remove it entirely. If it must exist, place it behind trusted network controls and strong authentication."
	if !server.PasswordConfigured {
		severity = model.SeverityCritical
		why = "Supervisor's web control panel is exposed on a broad address without a password, so unintended clients may be able to manage processes directly."
	}

	evidence := []model.Evidence{
		{Label: "config", Detail: server.ConfigPath},
		{Label: "bind", Detail: server.Bind},
	}
	if server.Username != "" {
		evidence = append(evidence, model.Evidence{Label: "username", Detail: server.Username})
	}
	if !server.PasswordConfigured {
		evidence = append(evidence, model.Evidence{Label: "auth", Detail: "password not configured"})
	}

	return model.Finding{
		ID:          buildFindingID(operationalNetworkCheckID, "supervisor_http_exposed", server.ConfigPath),
		CheckID:     operationalNetworkCheckID,
		Class:       model.FindingClassDirect,
		Severity:    severity,
		Confidence:  model.ConfidenceConfirmed,
		Title:       "Supervisor web control panel is exposed on a broad address",
		Why:         why,
		Remediation: remediation,
		Evidence:    evidence,
		Affected: []model.Target{
			{Type: "path", Path: server.ConfigPath},
		},
	}
}

func isBroadSupervisorBind(bind string) bool {
	address, _ := splitOperationalBind(strings.TrimSpace(bind))
	if isLoopbackListenerAddress(address) {
		return false
	}

	return isBroadListenerAddress(address)
}

func splitOperationalBind(value string) (string, string) {
	trimmedValue := strings.TrimSpace(value)
	if trimmedValue == "" {
		return "", ""
	}

	if strings.HasPrefix(trimmedValue, "[") {
		if separatorIndex := strings.LastIndex(trimmedValue, "]:"); separatorIndex >= 0 {
			return trimmedValue[1:separatorIndex], trimmedValue[separatorIndex+2:]
		}
	}

	separatorIndex := strings.LastIndex(trimmedValue, ":")
	if separatorIndex < 0 {
		return trimmedValue, ""
	}

	return trimmedValue[:separatorIndex], trimmedValue[separatorIndex+1:]
}
