package agent

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/quietls/agent/internal/httpclient"
	"github.com/quietls/agent/internal/platform"
	"github.com/quietls/agent/internal/webserver"
)

// SetupOptions holds the options for the setup/registration command.
type SetupOptions struct {
	Token        string
	BaseURL      string
	ConfigPath   string
	AgentVersion string
}

// SetupDeps holds injectable dependencies for the setup command.
type SetupDeps struct {
	Executor platform.Executor
	FileIO   FileIO
	Logger   *slog.Logger
}

// DefaultSetupDeps returns production dependencies.
func DefaultSetupDeps() SetupDeps {
	return SetupDeps{
		Executor: platform.OSExecutor{},
		FileIO:   OSFileIO{},
		Logger:   slog.Default(),
	}
}

// Setup registers the agent with the backend and saves the configuration.
func Setup(opts SetupOptions, deps SetupDeps) error {
	if opts.Token == "" {
		return fmt.Errorf("token is required (use --token or SSL_AGENT_TOKEN env var)")
	}
	if opts.BaseURL == "" {
		opts.BaseURL = "https://quietls.com/v1"
	}
	if opts.ConfigPath == "" {
		opts.ConfigPath = DefaultConfigPath
	}

	// Local development may use an HTTP backend, but production registration
	// must always happen over HTTPS to protect the setup token and the returned
	// long-lived agent credentials.
	insecureDev := os.Getenv("SSL_AGENT_INSECURE_DEV") == "1"
	if !insecureDev && !httpclient.IsSecureBaseURL(opts.BaseURL) {
		return fmt.Errorf("base URL must use https (set SSL_AGENT_INSECURE_DEV=1 to allow http for local development only)")
	}

	deps.Logger.Info("Collecting server context...")

	// Detect OS
	osInfo := platform.DetectOS(deps.Executor)
	deps.Logger.Info("Detected OS", "distro", osInfo.Distro, "version", osInfo.Version, "arch", osInfo.Arch)

	// Detect web server
	ws := webserver.DetectWebServer(deps.Executor)
	var wsCtx *httpclient.WebServerContext
	if ws != nil {
		deps.Logger.Info("Detected web server", "type", ws.Type, "version", ws.Version)
		wsCtx = &httpclient.WebServerContext{
			Type:    ws.Type,
			Version: ws.Version,
		}
	}

	// Detect runtime
	runtime := platform.DetectRuntime(deps.Executor)

	// Detect platform profile
	var wsType string
	if ws != nil {
		wsType = ws.Type
	}
	profile := platform.DetectProfile(osInfo, wsType, runtime)

	// Get hostname
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	// Register with backend
	deps.Logger.Info("Registering agent with backend...", "base_url", opts.BaseURL)

	client := httpclient.New(opts.BaseURL, "", "", nil)
	resp, err := client.Register(httpclient.RegisterRequest{
		Token:    opts.Token,
		Hostname: hostname,
		Context: httpclient.RegisterContext{
			OS: httpclient.OSContext{
				Distro:  osInfo.Distro,
				Version: osInfo.Version,
				Arch:    osInfo.Arch,
			},
			WebServer:       wsCtx,
			Runtime:         runtime,
			AgentVersion:    opts.AgentVersion,
			PlatformProfile: profile,
		},
	})
	if err != nil {
		return fmt.Errorf("registration failed: %w", err)
	}

	// Save config
	profileStr := profile
	cfg := &Config{
		AgentID:         resp.AgentID,
		AgentToken:      resp.AgentToken,
		AgentSecret:     resp.AgentSecret,
		BaseURL:         opts.BaseURL,
		PollInterval:    30,
		Version:         opts.AgentVersion,
		PlatformProfile: &profileStr,
	}

	if err := SaveConfig(cfg, opts.ConfigPath, deps.FileIO); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	deps.Logger.Info("Agent registered successfully",
		"agent_id", resp.AgentID,
		"config_path", opts.ConfigPath,
	)

	return nil
}
