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
			findings = append(findings, buildBroadListenerFinding(listener, "Redis listens on a broad network address", "Broad Redis exposure can hand session data, queues, and cache-backed secrets to remote attackers or adjacent tenants.", "Bind Redis to loopback or a tightly scoped private address and restrict access with network controls."))
		case listenerHasAnyProcessName(listener, "mysqld", "mariadbd") || listener.LocalPort == "3306":
			findings = append(findings, buildBroadListenerFinding(listener, "MySQL listens on a broad network address", "Broad MySQL exposure turns credential reuse or weak grants into remote database compromise paths.", "Restrict MySQL to loopback or an explicitly trusted internal address and keep public exposure behind intentional controls only."))
		case listenerHasAnyProcessName(listener, "postgres") || listener.LocalPort == "5432":
			findings = append(findings, buildBroadListenerFinding(listener, "Postgres listens on a broad network address", "Broad Postgres exposure increases remote attack surface and makes lateral movement through database credentials easier.", "Bind Postgres to loopback or a tightly scoped private address and review host-based access rules."))
		case listenerHasAnyProcessName(listener, "php-fpm", "php-fpm8.3", "php-fpm8.2") || listener.LocalPort == "9000":
			findings = append(findings, buildBroadListenerFinding(listener, "PHP-FPM appears reachable on a broad TCP listener", "Broad PHP-FPM TCP listeners weaken the intended local trust boundary and increase the chance of direct request injection against the PHP runtime.", "Prefer a Unix socket for local integration or restrict PHP-FPM TCP listeners to loopback or a tightly controlled private address."))
		case listenerHasAnyProcessName(listener, "php") && (listener.LocalPort == "8000" || listener.LocalPort == "8080"):
			findings = append(findings, buildBroadListenerFinding(listener, "A likely development server is listening on a broad network address", "Accidental development servers bypass the intended Nginx and PHP-FPM boundary and often expose debugging behavior or inconsistent routing.", "Shut down the development server and serve Laravel only through the intended production web stack."))
		case (listener.LocalPort == "6001" || listener.LocalPort == "6002") && (listenerHasAnyProcessName(listener, "node", "php") || len(listener.ProcessNames) == 0):
			findings = append(findings, buildBroadListenerFinding(listener, "An app-adjacent realtime or websocket service listens broadly", "Broad realtime or websocket listeners such as Reverb, Soketi, or Octane-adjacent services increase the exposed Laravel attack surface when they are not intentionally scoped.", "Bind realtime services to the intended interface only and confirm they sit behind the expected reverse-proxy and auth boundary."))
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
	why := "Supervisor's HTTP control surface should stay on loopback or another tightly scoped management address because it exposes process-management capabilities."
	remediation := "Bind Supervisor inet_http_server to loopback only or remove it entirely; if it must exist, require strong authentication."
	if !server.PasswordConfigured {
		severity = model.SeverityCritical
		why = "A broadly bound Supervisor HTTP control surface without a configured password can expose process-management access to unintended clients."
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
		Title:       "Supervisor HTTP control surface is broadly exposed",
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
