// Package config provides centralized configuration management
package config

import (
	"flag"
	"os"
	"strconv"
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
	NoBackoff              bool
	BufferSize             int
	WorkerCount            int
	StatsIntervalSec       int

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
	noBackoff := flag.Bool("no-backoff", false, "Disable exponential backoff for reconnections (reconnect immediately)")
	bufferSize := flag.Int("buffer-size", 50000, "Internal event buffer size for high-volume streams")
	workerCount := flag.Int("workers", 4, "Number of parallel workers for processing messages")
	statsInterval := flag.Int("stats-interval", 30, "Log processing stats every N seconds (0 to disable)")

	flag.Parse()

	// Parse flags
	cfg.Verbose = *verbose || *veryVerbose
	cfg.URLsOnly = *urlsOnly
	cfg.ReconnectTimeoutSec = *reconnectTimeoutSec
	cfg.MaxReconnectTimeoutSec = *maxReconnectTimeoutSec
	cfg.NoBackoff = *noBackoff
	cfg.BufferSize = *bufferSize
	cfg.WorkerCount = *workerCount
	cfg.StatsIntervalSec = *statsInterval

	// Parse domains from environment or command-line args
	cfg.Domains = parseDomains(flag.Args())

	// Parse environment variables
	cfg.WebSocketURL = os.Getenv("CERTSTREAM_URL")
	cfg.WebhookURL = os.Getenv("WEBHOOK_URL")
	cfg.APIToken = os.Getenv("API_TOKEN")

	// Override with environment variables if set (env vars take precedence over defaults, but not over flags)
	if os.Getenv("NO_BACKOFF") != "" {
		cfg.NoBackoff = os.Getenv("NO_BACKOFF") == "true" || os.Getenv("NO_BACKOFF") == "1"
	}
	if bufferEnv := os.Getenv("BUFFER_SIZE"); bufferEnv != "" {
		if size := parseInt(bufferEnv, cfg.BufferSize); size > 0 {
			cfg.BufferSize = size
		}
	}
	if workersEnv := os.Getenv("WORKERS"); workersEnv != "" {
		if count := parseInt(workersEnv, cfg.WorkerCount); count > 0 {
			cfg.WorkerCount = count
		}
	}
	if statsEnv := os.Getenv("STATS_INTERVAL"); statsEnv != "" {
		if interval := parseInt(statsEnv, cfg.StatsIntervalSec); interval >= 0 {
			cfg.StatsIntervalSec = interval
		}
	}

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

// parseInt safely parses an integer from a string, returning defaultValue on error
func parseInt(s string, defaultValue int) int {
	if val, err := strconv.Atoi(s); err == nil {
		return val
	}
	return defaultValue
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

// StatsInterval returns the stats logging interval as a Duration.
func (c *CLIConfig) StatsInterval() time.Duration {
	return time.Duration(c.StatsIntervalSec) * time.Second
}

// HasDomains returns true if domains are configured
func (c *CLIConfig) HasDomains() bool {
	return len(c.Domains) > 0
}

// HasWebhook returns true if webhook is configured
func (c *CLIConfig) HasWebhook() bool {
	return c.WebhookURL != ""
}
