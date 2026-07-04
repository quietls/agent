package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/quietls/agent/internal/agent"
	"github.com/quietls/agent/internal/platform"
	"github.com/quietls/agent/internal/webserver"
)

var version = "dev"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]

	switch cmd {
	case "setup":
		if err := runSetup(); err != nil {
			slog.Error("Setup failed", "error", err.Error())
			os.Exit(1)
		}
	case "daemon":
		if err := runDaemon(); err != nil {
			slog.Error("Daemon failed", "error", err.Error())
			os.Exit(1)
		}
	case "status":
		runStatus()
	case "renew":
		fmt.Println("Renew: not yet implemented")
	case "--version", "-v":
		fmt.Printf("ssl-agent %s\n", version)
	case "--help", "-h", "help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Printf(`ssl-agent %s — SSL automation agent

Usage:
  ssl-agent <command> [options]

Commands:
  setup     Register this agent with the backend
  daemon    Start the polling daemon
  status    Show agent and server status
  renew     Renew certificates (not yet implemented)

Options:
  --token, -t <token>    API token (or set SSL_AGENT_TOKEN)
  --base-url <url>       Backend URL (default: https://api.quietls.com/v1)
  --config <path>        Config file path (default: /etc/ssl-agent/config.json)
  --version              Show version
  --help                 Show this help
`, version)
}

func runSetup() error {
	token := ""
	baseURL := "https://api.quietls.com/v1"
	configPath := ""

	args := os.Args[2:]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--token", "-t":
			if i+1 < len(args) {
				i++
				token = args[i]
			}
		case "--base-url":
			if i+1 < len(args) {
				i++
				baseURL = args[i]
			}
		case "--config":
			if i+1 < len(args) {
				i++
				configPath = args[i]
			}
		}
	}

	// Fallback to env var
	if token == "" {
		token = os.Getenv("SSL_AGENT_TOKEN")
	}

	return agent.Setup(agent.SetupOptions{
		Token:        token,
		BaseURL:      baseURL,
		ConfigPath:   configPath,
		AgentVersion: version,
	}, agent.DefaultSetupDeps())
}

func runDaemon() error {
	configPath := ""

	args := os.Args[2:]
	for i := 0; i < len(args); i++ {
		if args[i] == "--config" && i+1 < len(args) {
			i++
			configPath = args[i]
		}
	}

	daemon := agent.NewDaemon(configPath, version, agent.DefaultDaemonDeps())
	return daemon.Start()
}

func runStatus() {
	configPath := ""
	args := os.Args[2:]
	for i := 0; i < len(args); i++ {
		if args[i] == "--config" && i+1 < len(args) {
			i++
			configPath = args[i]
		}
	}

	exe := platform.OSExecutor{}

	// Try to load config
	cfg, err := agent.LoadConfig(configPath, agent.OSFileIO{})
	if err != nil {
		fmt.Printf("Agent: not registered (config not found: %s)\n\n", agent.DefaultConfigPath)
	} else {
		fmt.Printf("Agent ID: %s\n", cfg.AgentID)
		fmt.Printf("Backend:  %s\n", cfg.BaseURL)
		fmt.Println()
	}

	// OS info
	osInfo := platform.DetectOS(exe)
	fmt.Printf("OS:       %s %s (%s)\n", osInfo.Distro, osInfo.Version, osInfo.Arch)

	// Runtime
	runtime := platform.DetectRuntime(exe)
	fmt.Printf("Runtime:  %s\n", runtime)

	// Web server
	ws := webserver.DetectWebServer(exe)
	if ws != nil {
		fmt.Printf("Web Server: %s %s (%d vhosts)\n", ws.Type, ws.Version, len(ws.Vhosts))
	} else {
		fmt.Println("Web Server: not detected")
	}

	// Ports
	ports := platform.DetectPorts(exe)
	fmt.Printf("Port 80:  %v\n", ports.Port80)
	fmt.Printf("Port 443: %v\n", ports.Port443)
}
