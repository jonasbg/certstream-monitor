// Package main provides a CLI for monitoring CertStream events.
// It supports filtering by domains, verbose output, and graceful shutdown.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/jonasbg/certstream-monitor/certstream"
)

var (
	infoColor    = color.New(color.FgCyan)
	domainColor  = color.New(color.FgGreen)
	warningColor = color.New(color.FgYellow)
)

// main parses command‑line flags, configures the CertStream monitor, and handles events.
func main() {
	// Flags define CLI options.
	verbose := flag.Bool("v", false, "Enable verbose output")
	veryVerbose := flag.Bool("verbose", false, "Enable verbose output")
	urlsOnly := flag.Bool("urls-only", false, "Output only URLs")
	reconnectTimeoutSec := flag.Int("reconnect-timeout", 1, "Base reconnection timeout in seconds")
	maxReconnectTimeoutSec := flag.Int("max-reconnect", 300, "Maximum reconnection timeout in seconds")
	flag.Parse()

	// Get domains from command-line arguments or TARGET_DOMAINS environment variable
	args := flag.Args()
	var domains []string

	// Check environment variable first
	if targetDomains := os.Getenv("TARGET_DOMAINS"); targetDomains != "" {
		// Support both comma and space-separated values
		targetDomains = strings.ReplaceAll(targetDomains, ",", " ")
		for _, domain := range strings.Fields(targetDomains) {
			domain = strings.TrimSpace(domain)
			if domain != "" {
				domains = append(domains, domain)
			}
		}
	}

	// Command-line args override environment variable
	if len(args) > 0 {
		domains = args
	}

	// Create options for the monitor
	options := []certstream.Option{
		certstream.WithDebug(*verbose || *veryVerbose),
		certstream.WithReconnectTimeout(time.Duration(*reconnectTimeoutSec) * time.Second),
		certstream.WithMaxReconnectTimeout(time.Duration(*maxReconnectTimeoutSec) * time.Second),
	}

	// Add domains if specified
	if len(domains) > 0 {
		options = append(options, certstream.WithDomains(domains))
		if *verbose || *veryVerbose {
			infoColor.Printf("Starting monitoring for domains: %v\n", domains)
		}
	} else if *verbose || *veryVerbose {
		infoColor.Println("No domains specified. Monitoring all certificates.")
	}

	// Set WebSocket URL from environment variable if provided
	if wsURL := os.Getenv("CERTSTREAM_URL"); wsURL != "" {
		options = append(options, certstream.WithWebSocketURL(wsURL))
	}

	// Set webhook URL from environment variable if provided
	if webhookURL := os.Getenv("WEBHOOK_URL"); webhookURL != "" {
		options = append(options, certstream.WithWebhookURL(webhookURL))
		if *verbose || *veryVerbose {
			infoColor.Printf("Webhook enabled: %s\n", webhookURL)
		}
	}

	// Set API token from environment variable if provided
	if apiToken := os.Getenv("API_TOKEN"); apiToken != "" {
		options = append(options, certstream.WithAPIToken(apiToken))
		if *verbose || *veryVerbose {
			infoColor.Println("API token configured for webhook authentication")
		}
	}

	if *verbose || *veryVerbose {
		wsURL := os.Getenv("CERTSTREAM_URL")
		if wsURL != "" {
			infoColor.Printf("Using CertStream URL: %s\n", wsURL)
		} else {
			infoColor.Printf("Using default CertStream URL: %s\n", certstream.DefaultWebSocketURL)
		}
		infoColor.Printf("Reconnection settings: base timeout: %ds, max timeout: %ds\n",
			*reconnectTimeoutSec, *maxReconnectTimeoutSec)
		infoColor.Println("Waiting for certificates... (Press CTRL+C to exit)")
	}

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
			processCertificateEvent(event, *urlsOnly, *verbose || *veryVerbose)

		case <-sigChan:
			if *verbose || *veryVerbose {
				fmt.Println("\nShutting down...")
			}
			monitor.Stop()
			return
		}
	}
}

// processCertificateEvent handles received certificate events based on configuration
// processCertificateEvent handles received certificate events based on flags.
// It prints domain information, optionally filtered to URLs only or verbose details.
func processCertificateEvent(event certstream.CertEvent, urlsOnly, verbose bool) {
	cert := event.Certificate
	timestamp := event.Timestamp.Format("2006-01-02T15:04:05")

	// Display all domains if no specific domains were matched (or no domains were specified)
	if len(event.MatchedDomains) == 0 {
		// When no domains are specified, display all certificate domains
		for _, domain := range cert.Data.LeafCert.AllDomains {
			if urlsOnly {
				fmt.Printf("%s\n", domain)
			} else if verbose {
				fmt.Printf("[%s] ", timestamp)
				fmt.Printf("%s", domain)
				fmt.Printf(" - ")
				domainColor.Printf("%s", cert.Data.LeafCert.Subject.CN)
				fmt.Printf("\n    Type: %s", event.CertType)
				fmt.Printf("\n    Issuer: %s", cert.Data.LeafCert.Issuer.O)
				fmt.Printf("\n    Valid: %s -> %s\n",
					time.Unix(int64(cert.Data.LeafCert.NotBefore), 0).Format("2006-01-02"),
					time.Unix(int64(cert.Data.LeafCert.NotAfter), 0).Format("2006-01-02"))
			} else {
				fmt.Printf("[%s] ", timestamp)
				fmt.Printf("%s", domain)
				fmt.Printf(" - ")
				domainColor.Printf("%s\n", cert.Data.LeafCert.Subject.CN)
			}

			// Only show the first domain in non-verbose mode to avoid flooding the output
			if !verbose && len(cert.Data.LeafCert.AllDomains) > 1 {
				break
			}
		}
		return
	}

	// If we're monitoring specific domains, display matched certificates
	for _, certDomain := range cert.Data.LeafCert.AllDomains {
		for _, watchDomain := range event.MatchedDomains {
			if certstream.IsDomainMatch(certDomain, watchDomain) {
				if urlsOnly {
					fmt.Printf("%s\n", certDomain)
				} else if verbose {
					fmt.Printf("[%s] ", timestamp)
					fmt.Printf("%s", certDomain)
					fmt.Printf(" - ")
					domainColor.Printf("%s", cert.Data.LeafCert.Subject.CN)
					warningColor.Printf(" (matched: %s)", watchDomain)
					fmt.Printf("\n    Type: %s", event.CertType)
					fmt.Printf("\n    Issuer: %s", cert.Data.LeafCert.Issuer.O)
					fmt.Printf("\n    Valid: %s -> %s\n",
						time.Unix(int64(cert.Data.LeafCert.NotBefore), 0).Format("2006-01-02"),
						time.Unix(int64(cert.Data.LeafCert.NotAfter), 0).Format("2006-01-02"))
				} else {
					fmt.Printf("[%s] ", timestamp)
					fmt.Printf("%s", certDomain)
					fmt.Printf(" - ")
					domainColor.Printf("%s\n", cert.Data.LeafCert.Subject.CN)
				}
				break
			}
		}
	}
}
