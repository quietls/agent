package commands

import (
	"fmt"

	"github.com/quietls/agent/internal/certs"
)

func handleMetricCertLocal(ctx HandlerContext) CommandResult {
	domain, _ := ctx.Parameters["domain"].(string)
	certPath, _ := ctx.Parameters["cert_path"].(string)

	if domain == "" {
		return CommandResult{
			Status: "failure",
			Output: map[string]any{},
			Error:  "domain parameter is required",
		}
	}

	var allowedPaths []string
	autoDetected := false

	// If cert_path not provided, detect from web server vhosts
	if certPath == "" {
		ws := ctx.detectWebServer()
		if ws != nil {
			for i := range ws.Vhosts {
				for _, name := range ws.Vhosts[i].ServerNames {
					if name == domain && ws.Vhosts[i].CertPath != "" {
						certPath = ws.Vhosts[i].CertPath
						autoDetected = true
						break
					}
				}
				if certPath != "" {
					break
				}
			}
		}
	}

	if certPath == "" {
		return CommandResult{
			Status: "failure",
			Output: map[string]any{},
			Error:  fmt.Sprintf("no certificate path found for domain %s", domain),
		}
	}

	// Auto-detected paths from local vhosts are trusted even if they fall
	// outside the default SSL roots (e.g. custom vhost configurations).
	if autoDetected {
		allowedPaths = append(allowedPaths, certPath)
	}
	if err := certs.ValidateCertPath(certPath, allowedPaths); err != nil {
		return CommandResult{
			Status: "failure",
			Output: map[string]any{},
			Error:  err.Error(),
		}
	}

	// Scan the certificate
	certList := certs.ScanCerts(ctx.Executor, []string{certPath})
	if len(certList) == 0 {
		return CommandResult{
			Status: "failure",
			Output: map[string]any{},
			Error:  fmt.Sprintf("failed to scan certificate at %s", certPath),
		}
	}

	cert := certList[0]

	output := map[string]any{
		"domain":  domain,
		"path":    certPath,
		"expires": cert.Expires,
		"subject": cert.Domain,
	}

	return CommandResult{
		Status: "success",
		Output: output,
	}
}
