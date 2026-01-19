// Package certstream provides a client for monitoring certificate transparency logs
package certstream

import (
	"context"
	"time"
)

// Default certstream websocket URL
const DefaultWebSocketURL = "wss://certstream.calidog.io/"

// CertData represents the certificate data structure from the CertStream service
type CertData struct {
	MessageType string `json:"message_type"`
	Data        struct {
		CertIndex  int64  `json:"cert_index"`
		CertLink   string `json:"cert_link"`
		UpdateType string `json:"update_type"`
		LeafCert   struct {
			AllDomains []string `json:"all_domains"`
			Extensions struct {
				AuthorityInfoAccess    string `json:"authorityInfoAccess"`
				AuthorityKeyIdentifier string `json:"authorityKeyIdentifier"`
				BasicConstraints       string `json:"basicConstraints"`
				KeyUsage               string `json:"keyUsage"`
				SubjectAltName         string `json:"subjectAltName"`
				SubjectKeyIdentifier   string `json:"subjectKeyIdentifier"`
			} `json:"extensions"`
			Fingerprint        string  `json:"fingerprint"`
			Sha1               string  `json:"sha1"`
			Sha256             string  `json:"sha256"`
			NotBefore          float64 `json:"not_before"`
			NotAfter           float64 `json:"not_after"`
			SerialNumber       string  `json:"serial_number"`
			SignatureAlgorithm string  `json:"signature_algorithm"`
			Subject            struct {
				C            interface{} `json:"C"`
				CN           string      `json:"CN"`
				L            interface{} `json:"L"`
				O            interface{} `json:"O"`
				OU           interface{} `json:"OU"`
				ST           interface{} `json:"ST"`
				Aggregated   string      `json:"aggregated"`
				EmailAddress interface{} `json:"email_address"`
			} `json:"subject"`
			Issuer struct {
				C            string      `json:"C"`
				CN           string      `json:"CN"`
				L            interface{} `json:"L"`
				O            string      `json:"O"`
				OU           interface{} `json:"OU"`
				ST           interface{} `json:"ST"`
				Aggregated   string      `json:"aggregated"`
				EmailAddress interface{} `json:"email_address"`
			} `json:"issuer"`
			IsCA bool `json:"is_ca"`
		} `json:"leaf_cert"`
		Seen   float64 `json:"seen"`
		Source struct {
			URL  string `json:"url"`
			Name string `json:"name"`
		} `json:"source"`
	} `json:"data"`
}

// CertEvent represents a certificate event with additional metadata
type CertEvent struct {
	Certificate    CertData
	Timestamp      time.Time
	CertType       string // "NEW" or "RENEWAL"
	MatchedDomains []string
}

// Config holds the configuration for the certificate monitor
type Config struct {
	WebSocketURL        string          // URL of the CertStream service
	Domains             []string        // Domains to monitor (empty means monitor all)
	Debug               bool            // Enable debug logging
	ReconnectTimeout    time.Duration   // Base time to wait before reconnecting after a failure
	MaxReconnectTimeout time.Duration   // Maximum reconnection timeout
	DisableBackoff      bool            // Disable exponential backoff for immediate reconnection
	BufferSize          int             // Size of the internal event buffer (default: 50000)
	WorkerCount         int             // Number of parallel workers for processing (default: 4)
	Context             context.Context // Context to control the monitor
}

// Option is a function that configures a Config
type Option func(*Config)

// WithWebSocketURL sets the WebSocket URL for the CertStream service
func WithWebSocketURL(url string) Option {
	return func(c *Config) {
		c.WebSocketURL = url
	}
}

// WithDomains sets the domains to monitor
func WithDomains(domains []string) Option {
	return func(c *Config) {
		c.Domains = domains
	}
}

// WithDebug enables debug logging
func WithDebug(debug bool) Option {
	return func(c *Config) {
		c.Debug = debug
	}
}

// WithReconnectTimeout sets the reconnection timeout
func WithReconnectTimeout(timeout time.Duration) Option {
	return func(c *Config) {
		c.ReconnectTimeout = timeout
	}
}

// WithMaxReconnectTimeout sets the maximum reconnection timeout
func WithMaxReconnectTimeout(timeout time.Duration) Option {
	return func(c *Config) {
		c.MaxReconnectTimeout = timeout
	}
}

// WithDisableBackoff disables exponential backoff for immediate reconnection
func WithDisableBackoff(disable bool) Option {
	return func(c *Config) {
		c.DisableBackoff = disable
	}
}

// WithBufferSize sets the internal event buffer size
func WithBufferSize(size int) Option {
	return func(c *Config) {
		c.BufferSize = size
	}
}

// WithWorkerCount sets the number of parallel workers for processing
func WithWorkerCount(count int) Option {
	return func(c *Config) {
		c.WorkerCount = count
	}
}

// WithContext sets the context for the monitor
func WithContext(ctx context.Context) Option {
	return func(c *Config) {
		c.Context = ctx
	}
}
