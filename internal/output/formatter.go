// Package output provides formatting and display utilities for certificate events
package output

import (
	"fmt"
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

// PrintStartupInfo prints startup information in verbose mode
func (f *Formatter) PrintStartupInfo(domains []string, wsURL, defaultURL, webhookURL string, reconnectSec, maxReconnectSec int) {
	// Always show which domains we're scanning for when domains are specified
	if len(domains) > 0 {
		f.infoColor.Printf("Scanning for domains: %v\n", domains)
	}

	if !f.verbose {
		return
	}

	if len(domains) == 0 {
		f.infoColor.Println("No domains specified. Monitoring all certificates.")
	}

	if wsURL != "" {
		f.infoColor.Printf("Using CertStream URL: %s\n", wsURL)
	} else {
		f.infoColor.Printf("Using default CertStream URL: %s\n", defaultURL)
	}

	f.infoColor.Printf("Reconnection settings: base timeout: %ds, max timeout: %ds\n",
		reconnectSec, maxReconnectSec)

	if webhookURL != "" {
		f.infoColor.Printf("Webhook enabled: %s\n", webhookURL)
	}

	f.infoColor.Println("Waiting for certificates... (Press CTRL+C to exit)")
}

// PrintShutdown prints shutdown message
func (f *Formatter) PrintShutdown() {
	if f.verbose {
		fmt.Println("\nShutting down...")
	}
}

// PrintWebhookConfigured prints webhook configuration message
func (f *Formatter) PrintWebhookConfigured() {
	if f.verbose {
		f.infoColor.Println("API token configured for webhook authentication")
	}
}
