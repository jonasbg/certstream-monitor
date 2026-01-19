// Package config provides centralized configuration management
package config

import (
	"flag"
	"os"
	"strings"
	"time"
)

// CLIConfig holds all configuration options for the CLI application
type CLIConfig struct {
	// Output options
	Verbose  bool
	URLsOnly bool

	// Connection options
	WebSocketURL           string
	ReconnectTimeoutSec    int
	MaxReconnectTimeoutSec int

	// Domain filtering
	Domains []string

	// Webhook options
	WebhookURL string
	APIToken   string
}

// ParseFromFlags parses command-line flags and environment variables
func ParseFromFlags() *CLIConfig {
	cfg := &CLIConfig{}

	// Define flags
	verbose := flag.Bool("v", false, "Enable verbose output")
	veryVerbose := flag.Bool("verbose", false, "Enable verbose output")
	urlsOnly := flag.Bool("urls-only", false, "Output only URLs")
	reconnectTimeoutSec := flag.Int("reconnect-timeout", 1, "Base reconnection timeout in seconds")
	maxReconnectTimeoutSec := flag.Int("max-reconnect", 300, "Maximum reconnection timeout in seconds")

	flag.Parse()

	// Parse flags
	cfg.Verbose = *verbose || *veryVerbose
	cfg.URLsOnly = *urlsOnly
	cfg.ReconnectTimeoutSec = *reconnectTimeoutSec
	cfg.MaxReconnectTimeoutSec = *maxReconnectTimeoutSec

	// Parse domains from environment or command-line args
	cfg.Domains = parseDomains(flag.Args())

	// Parse environment variables
	cfg.WebSocketURL = os.Getenv("CERTSTREAM_URL")
	cfg.WebhookURL = os.Getenv("WEBHOOK_URL")
	cfg.APIToken = os.Getenv("API_TOKEN")

	return cfg
}

// parseDomains extracts domains from command-line arguments or TARGET_DOMAINS env var
func parseDomains(args []string) []string {
	var domains []string

	// Check environment variable first
	if targetDomains := os.Getenv("TARGET_DOMAINS"); targetDomains != "" {
		domains = sanitizeDomains(targetDomains)
	}

	// Command-line args override environment variable
	if len(args) > 0 {
		domains = args
	}

	return domains
}

// sanitizeDomains splits and cleans domain strings from environment variables
func sanitizeDomains(input string) []string {
	// Support both comma and space-separated values
	input = strings.ReplaceAll(input, ",", " ")
	var domains []string

	for _, domain := range strings.Fields(input) {
		domain = strings.TrimSpace(domain)
		if domain != "" {
			domains = append(domains, domain)
		}
	}

	return domains
}

// ReconnectTimeout returns the reconnection timeout as a Duration
func (c *CLIConfig) ReconnectTimeout() time.Duration {
	return time.Duration(c.ReconnectTimeoutSec) * time.Second
}

// MaxReconnectTimeout returns the maximum reconnection timeout as a Duration
func (c *CLIConfig) MaxReconnectTimeout() time.Duration {
	return time.Duration(c.MaxReconnectTimeoutSec) * time.Second
}

// HasDomains returns true if domains are configured
func (c *CLIConfig) HasDomains() bool {
	return len(c.Domains) > 0
}

// HasWebhook returns true if webhook is configured
func (c *CLIConfig) HasWebhook() bool {
	return c.WebhookURL != ""
}
