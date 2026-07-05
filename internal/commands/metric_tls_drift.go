package commands

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"

	"github.com/quietls/agent/internal/webserver"
)

var (
	nginxServerNameRe = regexp.MustCompile(`(?m)^\s*server_name\s+([^;]+);`)
	apacheServerNameRe = regexp.MustCompile(`(?mi)^\s*(?:ServerName|ServerAlias)\s+([^\s#]+)`)
)

func handleMetricTlsDrift(ctx HandlerContext) CommandResult {
	domain, _ := ctx.Parameters["domain"].(string)
	baselineHash, _ := ctx.Parameters["baseline_hash"].(string)

	if domain == "" {
		return CommandResult{
			Status: "failure",
			Output: map[string]any{},
			Error:  "domain parameter is required",
		}
	}

	ws := ctx.detectWebServer()
	if ws == nil {
		return CommandResult{
			Status: "failure",
			Output: map[string]any{},
			Error:  "no web server detected",
		}
	}

	// Find vhost for the domain
	var vhost *webserver.VhostInfo
	for i := range ws.Vhosts {
		for _, name := range ws.Vhosts[i].ServerNames {
			if name == domain {
				vhost = &ws.Vhosts[i]
				break
			}
		}
		if vhost != nil {
			break
		}
	}

	if vhost == nil {
		return CommandResult{
			Status: "failure",
			Output: map[string]any{},
			Error:  fmt.Sprintf("no vhost found for domain %s", domain),
		}
	}

	// Read the config file
	data, err := ctx.Executor.ReadFile(vhost.ConfigPath)
	if err != nil {
		return CommandResult{
			Status: "failure",
			Output: map[string]any{},
			Error:  fmt.Sprintf("failed to read config: %v", err),
		}
	}

	// Compute hash of the relevant server block
	currentHash := computeConfigHash(string(data), domain, ws.Type)
	driftDetected := baselineHash != "" && baselineHash != currentHash

	output := map[string]any{
		"domain":         domain,
		"config_path":    vhost.ConfigPath,
		"web_server":     ws.Type,
		"current_hash":   currentHash,
		"baseline_hash":  baselineHash,
		"drift_detected": driftDetected,
	}

	if driftDetected {
		output["message"] = "TLS configuration has changed since last scan"
	} else {
		output["message"] = "TLS configuration matches baseline"
	}

	return CommandResult{
		Status: "success",
		Output: output,
	}
}

// computeConfigHash extracts the server block for the given domain and computes its SHA-256 hash.
func computeConfigHash(content, domain, wsType string) string {
	var block string

	if wsType == "nginx" {
		block = extractNginxServerBlock(content, domain)
	} else {
		block = extractApacheVhostBlock(content, domain)
	}

	if block == "" {
		// Fallback: hash the entire config file
		h := sha256.Sum256([]byte(content))
		return "sha256:" + hex.EncodeToString(h[:])
	}

	// Normalize: strip whitespace variations
	normalized := normalizeBlock(block)
	h := sha256.Sum256([]byte(normalized))
	return "sha256:" + hex.EncodeToString(h[:])
}

func extractNginxServerBlock(content, domain string) string {
	var blocks []string
	lines := strings.Split(content, "\n")
	depth := 0
	inServer := false
	var current strings.Builder

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		if !inServer && strings.HasPrefix(trimmed, "server") && strings.Contains(trimmed, "{") {
			inServer = true
			depth = 1
			current.Reset()
			current.WriteString(line + "\n")
			continue
		}

		if !inServer && strings.HasPrefix(trimmed, "server") {
			inServer = true
			depth = 0
			current.Reset()
			current.WriteString(line + "\n")
			continue
		}

		if inServer {
			current.WriteString(line + "\n")
			depth += strings.Count(line, "{") - strings.Count(line, "}")

			if depth <= 0 {
				blocks = append(blocks, current.String())
				inServer = false
			}
		}
	}

	for _, block := range blocks {
		if blockHasExactServerName(block, domain, nginxServerNameRe) {
			return block
		}
	}
	return ""
}

func extractApacheVhostBlock(content, domain string) string {
	lines := strings.Split(content, "\n")
	inBlock := false
	var block strings.Builder

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(strings.ToLower(trimmed), "<virtualhost") {
			inBlock = true
			block.Reset()
		}

		if inBlock {
			block.WriteString(line + "\n")
		}

		if strings.Contains(strings.ToLower(trimmed), "</virtualhost>") {
			inBlock = false
			blockStr := block.String()
			if blockHasExactServerName(blockStr, domain, apacheServerNameRe) {
				return blockStr
			}
		}
	}
	return ""
}

// blockHasExactServerName reports whether any ServerName/server_name directive
// inside the block names the domain exactly. Avoids substring false matches
// (e.g. "example.com" matching a block whose name is "foo.example.com").
func blockHasExactServerName(block, domain string, re *regexp.Regexp) bool {
	for _, m := range re.FindAllStringSubmatch(block, -1) {
		if len(m) < 2 {
			continue
		}
		for _, name := range strings.Fields(m[1]) {
			if strings.EqualFold(name, domain) {
				return true
			}
		}
	}
	return false
}

func normalizeBlock(block string) string {
	lines := strings.Split(block, "\n")
	var normalized strings.Builder
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			normalized.WriteString(trimmed + "\n")
		}
	}
	return normalized.String()
}
