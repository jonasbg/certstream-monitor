// Package output provides formatting and display utilities for certificate events
package output

import (
	"fmt"
	"os"
	"time"

	"github.com/fatih/color"
	"github.com/jonasbg/certstream-monitor/certstream"
)

// Formatter handles certificate event output formatting
type Formatter struct {
	urlsOnly bool
	verbose  bool

	infoColor    *color.Color
	domainColor  *color.Color
	warningColor *color.Color
}

// NewFormatter creates a new output formatter with the specified options
func NewFormatter(urlsOnly, verbose bool) *Formatter {
	return &Formatter{
		urlsOnly:     urlsOnly,
		verbose:      verbose,
		infoColor:    color.New(color.FgCyan),
		domainColor:  color.New(color.FgGreen),
		warningColor: color.New(color.FgYellow),
	}
}

// FormatEvent formats and prints a certificate event based on configuration
func (f *Formatter) FormatEvent(event certstream.CertEvent) {
	cert := event.Certificate
	timestamp := event.Timestamp.Format("2006-01-02T15:04:05")

	// Display all domains if no specific domains were matched
	if len(event.MatchedDomains) == 0 {
		f.formatUnfilteredDomains(cert, timestamp, event.CertType)
		return
	}

	// Display matched domains
	f.formatMatchedDomains(cert, timestamp, event)
}

// formatUnfilteredDomains formats output when no domain filtering is active
func (f *Formatter) formatUnfilteredDomains(cert certstream.CertData, timestamp, certType string) {
	for i, domain := range cert.Data.LeafCert.AllDomains {
		if f.urlsOnly {
			fmt.Printf("%s\n", domain)
		} else {
			f.printDomainLine(domain, cert.Data.LeafCert.Subject.CN, timestamp, "")
			if f.verbose {
				f.printVerboseDetails(cert, certType)
			}
		}

		// Only show first domain in non-verbose mode to avoid flooding
		if !f.verbose && len(cert.Data.LeafCert.AllDomains) > 1 {
			break
		}

		// Only show the first domain when not verbose
		if !f.verbose && i == 0 {
			break
		}
	}
}

// formatMatchedDomains formats output for matched domains
func (f *Formatter) formatMatchedDomains(cert certstream.CertData, timestamp string, event certstream.CertEvent) {
	for _, certDomain := range cert.Data.LeafCert.AllDomains {
		for _, watchDomain := range event.MatchedDomains {
			if certstream.IsDomainMatch(certDomain, watchDomain) {
				if f.urlsOnly {
					fmt.Printf("%s\n", certDomain)
				} else {
					matchedWith := ""
					if f.verbose {
						matchedWith = watchDomain
					}
					f.printDomainLine(certDomain, cert.Data.LeafCert.Subject.CN, timestamp, matchedWith)
					if f.verbose {
						f.printVerboseDetails(cert, event.CertType)
					}
				}
				break
			}
		}
	}
}

// printDomainLine prints a single domain line with timestamp and common name
func (f *Formatter) printDomainLine(domain, cn, timestamp, matchedWith string) {
	fmt.Printf("[%s] %s - ", timestamp, domain)
	f.domainColor.Printf("%s", cn)

	if matchedWith != "" {
		f.warningColor.Printf(" (matched: %s)", matchedWith)
	}

	fmt.Println()
}

// printVerboseDetails prints detailed certificate information
func (f *Formatter) printVerboseDetails(cert certstream.CertData, certType string) {
	notBefore := time.Unix(int64(cert.Data.LeafCert.NotBefore), 0).Format("2006-01-02")
	notAfter := time.Unix(int64(cert.Data.LeafCert.NotAfter), 0).Format("2006-01-02")

	fmt.Printf("    Type: %s\n", certType)
	fmt.Printf("    Issuer: %s\n", cert.Data.LeafCert.Issuer.O)
	fmt.Printf("    Valid: %s -> %s\n", notBefore, notAfter)
}

// PrintStartupInfo prints comprehensive startup configuration
func (f *Formatter) PrintStartupInfo(domains []string, wsURL, defaultURL, webhookURL string, reconnectSec, maxReconnectSec int, noBackoff bool, bufferSize, workers, statsInterval int, apiToken string) {
	f.infoColor.Println("=== CertStream Monitor Configuration ===")

	// Print environment variables being used
	f.printEnvVariables()

	// Domain configuration
	if len(domains) > 0 {
		f.infoColor.Printf("Target Domains: %v\n", domains)
	} else {
		f.warningColor.Println("Target Domains: ALL (no filtering)")
	}

	// WebSocket URL
	if wsURL != "" {
		f.infoColor.Printf("WebSocket URL: %s\n", wsURL)
	} else {
		f.infoColor.Printf("WebSocket URL: %s (default)\n", defaultURL)
	}

	// Connection settings
	if noBackoff {
		f.infoColor.Println("Reconnection: Immediate (no backoff)")
	} else {
		f.infoColor.Printf("Reconnection: Base timeout: %ds, Max timeout: %ds (exponential backoff)\n",
			reconnectSec, maxReconnectSec)
	}

	// Performance settings
	f.infoColor.Printf("Buffer Size: %d\n", bufferSize)
	f.infoColor.Printf("Worker Count: %d\n", workers)
	if statsInterval > 0 {
		f.infoColor.Printf("Stats Interval: %ds\n", statsInterval)
	} else {
		f.infoColor.Println("Stats Interval: Disabled")
	}

	// Webhook configuration
	if webhookURL != "" {
		f.infoColor.Printf("Webhook URL: %s\n", webhookURL)
		if apiToken != "" {
			maskedToken := maskToken(apiToken)
			f.infoColor.Printf("API Token: %s\n", maskedToken)
		} else {
			f.warningColor.Println("API Token: (not set)")
		}
	} else {
		f.infoColor.Println("Webhook: Disabled")
	}

	// Output mode
	if f.urlsOnly {
		f.infoColor.Println("Output Mode: URLs only")
	} else if f.verbose {
		f.infoColor.Println("Output Mode: Verbose")
	} else {
		f.infoColor.Println("Output Mode: Normal")
	}

	f.infoColor.Println("========================================")
	f.infoColor.Println("Waiting for certificates... (Press CTRL+C to exit)")
	fmt.Println()
}

// printEnvVariables prints the environment variables used by the monitor
func (f *Formatter) printEnvVariables() {
	f.infoColor.Println("Environment Variables:")

	envVars := []struct {
		name   string
		mask   bool
	}{
		{"CERTSTREAM_URL", false},
		{"WEBHOOK_URL", false},
		{"API_TOKEN", true},
		{"TARGET_DOMAINS", false},
		{"NO_BACKOFF", false},
		{"BUFFER_SIZE", false},
		{"WORKERS", false},
		{"STATS_INTERVAL", false},
	}

	for _, env := range envVars {
		value := os.Getenv(env.name)
		if value == "" {
			fmt.Printf("  %s: (not set)\n", env.name)
		} else if env.mask {
			fmt.Printf("  %s: %s\n", env.name, maskToken(value))
		} else {
			fmt.Printf("  %s: %s\n", env.name, value)
		}
	}
	fmt.Println()
}

// PrintShutdown prints shutdown message
func (f *Formatter) PrintShutdown() {
	if f.verbose {
		fmt.Println("\nShutting down...")
	}
}

// maskToken masks an API token for display, showing only first and last 4 characters
func maskToken(token string) string {
	if token == "" {
		return "(not set)"
	}
	if len(token) <= 8 {
		return "****"
	}
	return token[:4] + "****" + token[len(token)-4:]
}
