// Package main provides a CLI for monitoring CertStream events.
// It supports filtering by domains, verbose output, and graceful shutdown.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/jonasbg/certstream-monitor/certstream"
	"github.com/jonasbg/certstream-monitor/internal/config"
	"github.com/jonasbg/certstream-monitor/internal/output"
	"github.com/jonasbg/certstream-monitor/internal/webhook"
)

// main parses command-line flags, configures the CertStream monitor, and handles events.
func main() {
	// Parse configuration from flags and environment
	cfg := config.ParseFromFlags()

	// Create output formatter
	formatter := output.NewFormatter(cfg.URLsOnly, cfg.Verbose)

	// Print startup information
	wsURL := cfg.WebSocketURL
	if wsURL == "" {
		wsURL = ""
	}
	formatter.PrintStartupInfo(
		cfg.Domains,
		wsURL,
		certstream.DefaultWebSocketURL,
		cfg.WebhookURL,
		cfg.ReconnectTimeoutSec,
		cfg.MaxReconnectTimeoutSec,
	)

	if cfg.HasWebhook() && cfg.APIToken != "" {
		formatter.PrintWebhookConfigured()
	}

	// Create webhook client if configured
	var webhookClient *webhook.Client
	if cfg.HasWebhook() {
		webhookClient = webhook.NewClient(cfg.WebhookURL, cfg.APIToken)
	}

	// Build monitor options
	options := buildMonitorOptions(cfg)

	// Create and start the monitor
	monitor := certstream.New(options...)
	monitor.Start()

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Process certificates
	for {
		select {
		case event := <-monitor.Events():
			formatter.FormatEvent(event)

			// Send webhook notifications for matched domains
			if webhookClient != nil && len(event.MatchedDomains) > 0 {
				sendWebhookNotifications(webhookClient, event)
			}

		case <-sigChan:
			formatter.PrintShutdown()
			monitor.Stop()
			return
		}
	}
}

// buildMonitorOptions creates monitor options from configuration
func buildMonitorOptions(cfg *config.CLIConfig) []certstream.Option {
	options := []certstream.Option{
		certstream.WithDebug(cfg.Verbose),
		certstream.WithReconnectTimeout(cfg.ReconnectTimeout()),
		certstream.WithMaxReconnectTimeout(cfg.MaxReconnectTimeout()),
		certstream.WithDisableBackoff(cfg.NoBackoff),
		certstream.WithBufferSize(cfg.BufferSize),
		certstream.WithWorkerCount(cfg.WorkerCount),
	}

	if cfg.HasDomains() {
		options = append(options, certstream.WithDomains(cfg.Domains))
	}

	if cfg.WebSocketURL != "" {
		options = append(options, certstream.WithWebSocketURL(cfg.WebSocketURL))
	}

	return options
}

// sendWebhookNotifications sends webhook notifications for matched domains
func sendWebhookNotifications(client *webhook.Client, event certstream.CertEvent) {
	ctx := context.Background()

	// Send notification for each matched domain
	for _, certDomain := range event.Certificate.Data.LeafCert.AllDomains {
		for _, watchDomain := range event.MatchedDomains {
			if certstream.IsDomainMatch(certDomain, watchDomain) {
				// Fire and forget - don't block on webhook sends
				go func(domain string) {
					_ = client.Send(ctx, event, domain)
				}(certDomain)
				break
			}
		}
	}
}
