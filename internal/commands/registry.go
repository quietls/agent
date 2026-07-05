package commands

import (
	"fmt"

	"github.com/quietls/agent/internal/certs"
	"github.com/quietls/agent/internal/httpclient"
	"github.com/quietls/agent/internal/platform"
	"github.com/quietls/agent/internal/webserver"
)

// CommandResult holds the output of a command handler.
type CommandResult struct {
	Status string         `json:"status"`
	Output map[string]any `json:"output"`
	Error  string         `json:"error,omitempty"`
}

// HandlerContext provides dependencies to command handlers.
type HandlerContext struct {
	Parameters map[string]any
	Executor   platform.Executor
	HTTPClient *httpclient.Client
	ConfigPath string
}

// detectWebServer resolves the web server using the agent's configured
// config_path override (for sidecar deployments without a local nginx binary)
// when set, falling back to standard binary-based detection otherwise.
func (ctx HandlerContext) detectWebServer() *webserver.WebServerInfo {
	opts := webserver.DetectOptions{}
	if ctx.ConfigPath != "" {
		opts.ConfigPathOverride = ctx.ConfigPath
	}
	return webserver.DetectWebServerWithOptions(ctx.Executor, opts)
}

// Handler is a function that executes a command.
type Handler func(ctx HandlerContext) CommandResult

// registry maps command IDs to their handlers.
var registry = map[string]Handler{
	"cert.scan":                 handleCertScan,
	"cert.install":              handleCertInstall,
	"webserver.detect":          handleWebserverDetect,
	"webserver.reload":          handleWebserverReload,
	"webserver.config.validate": handleWebserverConfigValidate,
	"agent.status":              handleAgentStatus,
	"diag.connectivity":         handleDiagConnectivity,
	"metric.tls-drift":          handleMetricTlsDrift,
	"metric.cert-local":         handleMetricCertLocal,
}

// GetHandler returns the handler for a command ID, or nil if not found.
func GetHandler(commandID string) Handler {
	return registry[commandID]
}

// GetSupportedCommands returns a list of all registered command IDs.
func GetSupportedCommands() []string {
	cmds := make([]string, 0, len(registry))
	for id := range registry {
		cmds = append(cmds, id)
	}
	return cmds
}

// ── Handlers ────────────────────────────────────────────────────

func handleCertScan(ctx HandlerContext) CommandResult {
	ws := ctx.detectWebServer()
	certPaths := collectCertPathsFromWebServer(ws)
	certList := certs.ScanCerts(ctx.Executor, certPaths)

	certsOut := make([]any, len(certList))
	for i, c := range certList {
		certsOut[i] = map[string]any{
			"domain":  c.Domain,
			"expires": c.Expires,
			"path":    c.Path,
		}
	}

	return CommandResult{
		Status: "success",
		Output: map[string]any{"certs": certsOut},
	}
}

func handleWebserverDetect(ctx HandlerContext) CommandResult {
	info := ctx.detectWebServer()

	output := map[string]any{"web_server": nil, "domains": []string{}}
	if info != nil {
		domains := make([]string, len(info.Vhosts))
		vhosts := make([]map[string]any, len(info.Vhosts))
		for i, v := range info.Vhosts {
			domains[i] = v.ServerName
			vhost := map[string]any{
				"server_name":  v.ServerName,
				"server_names": v.ServerNames,
				"config_path":  v.ConfigPath,
				"ssl_enabled":  v.SSLEnabled,
			}
			if v.CertPath != "" {
				vhost["cert_path"] = v.CertPath
			}
			if v.CertKeyPath != "" {
				vhost["cert_key_path"] = v.CertKeyPath
			}
			if len(v.ListenPorts) > 0 {
				vhost["listen_ports"] = v.ListenPorts
			}
			if v.IsDefault {
				vhost["is_default"] = true
			}
			if v.RedirectToHTTPS {
				vhost["redirect_to_https"] = true
			}
			vhosts[i] = vhost
		}
		wsInfo := map[string]any{
			"type":    info.Type,
			"version": info.Version,
		}
		if info.ConfigPath != "" {
			wsInfo["config_path"] = info.ConfigPath
		}
		if info.ConfigSource != "" {
			wsInfo["config_source"] = info.ConfigSource
		}
		output["web_server"] = wsInfo
		output["domains"] = domains
		output["vhosts"] = vhosts
	}

	return CommandResult{
		Status: "success",
		Output: output,
	}
}

func handleWebserverReload(ctx HandlerContext) CommandResult {
	// Try nginx first
	_, _, err := ctx.Executor.ExecCommand("nginx", "-s", "reload")
	if err == nil {
		return CommandResult{
			Status: "success",
			Output: map[string]any{"reloaded": "nginx"},
		}
	}

	// Fallback to apache
	_, _, err = ctx.Executor.ExecCommand("systemctl", "reload", "apache2")
	if err == nil {
		return CommandResult{
			Status: "success",
			Output: map[string]any{"reloaded": "apache2"},
		}
	}

	return CommandResult{
		Status: "failure",
		Output: map[string]any{},
		Error:  fmt.Sprintf("failed to reload web server: %v", err),
	}
}

func handleWebserverConfigValidate(ctx HandlerContext) CommandResult {
	// Try nginx first
	stdout, stderr, err := ctx.Executor.ExecCommand("nginx", "-t")
	if err == nil {
		return CommandResult{
			Status: "success",
			Output: map[string]any{"valid": true, "output": stdout + stderr, "server": "nginx"},
		}
	}

	// Fallback to Apache config test
	_, stderr2, err2 := ctx.Executor.ExecCommand("apachectl", "configtest")
	if err2 == nil {
		return CommandResult{
			Status: "success",
			Output: map[string]any{"valid": true, "output": stderr2, "server": "apache"},
		}
	}

	return CommandResult{
		Status: "failure",
		Output: map[string]any{"valid": false, "output": stderr},
		Error:  "config validation failed for both nginx and apache",
	}
}

func handleAgentStatus(ctx HandlerContext) CommandResult {
	osInfo := platform.DetectOS(ctx.Executor)
	ws := ctx.detectWebServer()
	certPaths := collectCertPathsFromWebServer(ws)
	certList := certs.ScanCerts(ctx.Executor, certPaths)
	ports := platform.DetectPorts(ctx.Executor)

	output := map[string]any{
		"os":            map[string]any{"distro": osInfo.Distro, "version": osInfo.Version, "arch": osInfo.Arch},
		"certs_managed": len(certList),
		"ports":         map[string]any{"port_80": ports.Port80, "port_443": ports.Port443},
	}

	if ws != nil {
		output["web_server"] = map[string]any{"type": ws.Type, "version": ws.Version}
	}

	return CommandResult{
		Status: "success",
		Output: output,
	}
}

// collectCertPathsFromWebServer extracts cert paths from an already-detected web server.
func collectCertPathsFromWebServer(ws *webserver.WebServerInfo) []string {
	if ws == nil {
		return nil
	}
	var paths []string
	for _, v := range ws.Vhosts {
		if v.CertPath != "" {
			paths = append(paths, v.CertPath)
		}
	}
	return paths
}

func handleDiagConnectivity(ctx HandlerContext) CommandResult {
	if ctx.HTTPClient == nil {
		return CommandResult{
			Status: "failure",
			Output: map[string]any{"backend_reachable": false},
			Error:  "no HTTP client available",
		}
	}

	_, err := ctx.HTTPClient.GetConfig()
	if err != nil {
		return CommandResult{
			Status: "failure",
			Output: map[string]any{"backend_reachable": false},
		}
	}

	return CommandResult{
		Status: "success",
		Output: map[string]any{"backend_reachable": true},
	}
}
