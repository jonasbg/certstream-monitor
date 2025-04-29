// Package certstream provides a client for monitoring certificate transparency logs
package certstream

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/fatih/color"
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
	WebSocketURL     string          // URL of the CertStream service
	Domains          []string        // Domains to monitor (empty means monitor all)
	Debug            bool            // Enable debug logging
	ReconnectTimeout time.Duration   // Time to wait before reconnecting after a failure
	Context          context.Context // Context to control the monitor
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

// WithContext sets the context for the monitor
func WithContext(ctx context.Context) Option {
	return func(c *Config) {
		c.Context = ctx
	}
}

// Monitor is the certstream client that monitors certificate transparency logs
type Monitor struct {
	config     Config
	eventsChan chan CertEvent
	stopChan   chan struct{}
	logger     Logger
	wg         sync.WaitGroup
	mu         sync.Mutex
	isRunning  bool
}

// Logger is the interface for logging
type Logger interface {
	Debug(format string, v ...interface{})
	Error(format string, v ...interface{})
	Info(format string, v ...interface{})
}

// defaultLogger is the default logger implementation
type defaultLogger struct {
	debug bool
}

func (l *defaultLogger) Debug(format string, v ...interface{}) {
	if l.debug {
		fmt.Printf("[DEBUG] "+format+"\n", v...)
	}
}

func (l *defaultLogger) Error(format string, v ...interface{}) {
	errorMsg := fmt.Sprintf(format, v...)

	// List of errors to suppress
	suppressedErrors := []string{
		"read limited at 32769 bytes",
		"failed to read frame payload: unexpected EOF",
		"failed to get reader: failed to read frame header: unexpected EOF",
		"received close frame: status = StatusNormalClosure", // <- suppress normal closures
	}

	for _, suppressed := range suppressedErrors {
		if strings.Contains(errorMsg, suppressed) {
			return
		}
	}

	if color.NoColor {
		fmt.Printf("[ERROR] "+format+"\n", v...)
	} else {
		color.New(color.FgRed).Printf("[ERROR] "+format+"\n", v...)
	}
}

func (l *defaultLogger) Info(format string, v ...interface{}) {
	if color.NoColor {
		fmt.Printf("[INFO] "+format+"\n", v...)
	} else {
		color.New(color.FgCyan).Printf("[INFO] "+format+"\n", v...)
	}
}

// New creates a new certificate monitor with the given options
func New(options ...Option) *Monitor {
	config := Config{
		WebSocketURL:     DefaultWebSocketURL,
		Domains:          []string{},
		Debug:            false,
		ReconnectTimeout: time.Second,
		Context:          context.Background(),
	}

	for _, option := range options {
		option(&config)
	}

	return &Monitor{
		config:     config,
		eventsChan: make(chan CertEvent, 100),
		stopChan:   make(chan struct{}),
		logger:     &defaultLogger{debug: config.Debug},
	}
}

// SetLogger sets a custom logger for the monitor
func (m *Monitor) SetLogger(logger Logger) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.logger = logger
}

// Events returns the channel for certificate events
func (m *Monitor) Events() <-chan CertEvent {
	return m.eventsChan
}

// Start starts the certificate monitoring process
func (m *Monitor) Start() {
	m.mu.Lock()
	if m.isRunning {
		m.mu.Unlock()
		return
	}
	m.isRunning = true
	m.mu.Unlock()

	m.wg.Add(1)
	go m.monitor()
}

// Stop stops the certificate monitoring process
func (m *Monitor) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.isRunning {
		return
	}

	close(m.stopChan)
	m.wg.Wait()
	m.isRunning = false

	// Create a new stopChan for future Start calls
	m.stopChan = make(chan struct{})
}

// IsDomainMatch checks if a certificate domain matches a monitored domain
func IsDomainMatch(certDomain, watchDomain string) bool {
	// Check for empty domains first
	if certDomain == "" || watchDomain == "" {
		return false
	}

	certParts := strings.Split(strings.ToLower(certDomain), ".")
	watchParts := strings.Split(strings.ToLower(watchDomain), ".")

	// Certificate domain must have at least as many parts as watch domain
	if len(certParts) < len(watchParts) {
		return false
	}

	// Check if the rightmost parts match the watch domain
	// For example: www.nhn.no matches nhn.no
	// But mynhn.no does not match nhn.no
	certIndex := len(certParts) - len(watchParts)
	for i := range watchParts {
		if certParts[certIndex+i] != watchParts[i] {
			return false
		}
	}
	return true
}

// monitor is the internal monitoring loop
func (m *Monitor) monitor() {
	defer m.wg.Done()

	ctx, cancel := context.WithCancel(m.config.Context)
	defer cancel()

	// Set up cancellation on stop
	go func() {
		select {
		case <-m.stopChan:
			cancel()
		case <-ctx.Done():
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopChan:
			return
		default:
			m.connectAndProcess(ctx)

			// Check if we should exit
			select {
			case <-ctx.Done():
				return
			case <-m.stopChan:
				return
			default:
				m.logger.Info("Connection lost. Reconnecting in %v...", m.config.ReconnectTimeout)
				time.Sleep(m.config.ReconnectTimeout)
			}
		}
	}
}

// connectAndProcess establishes the websocket connection and processes incoming certificates
func (m *Monitor) connectAndProcess(ctx context.Context) {
	m.logger.Debug("Connecting to %s", m.config.WebSocketURL)

	conn, _, err := websocket.Dial(ctx, m.config.WebSocketURL, nil)
	if err != nil {
		m.logger.Error("Connection error: %v", err)
		return
	}
	defer conn.Close(websocket.StatusAbnormalClosure, "")

	m.logger.Debug("Connected to CertStream service")

	for {
		select {
		case <-ctx.Done():
			conn.Close(websocket.StatusNormalClosure, "")
			return
		case <-m.stopChan:
			conn.Close(websocket.StatusNormalClosure, "")
			return
		default:
			_, data, err := conn.Read(ctx)
			if err != nil {
				m.logger.Error("Read error: %v", err)
				return
			}

			var cert CertData
			if err := json.Unmarshal(data, &cert); err != nil {
				m.logger.Error("JSON error: %v", err)
				continue
			}

			if cert.MessageType != "certificate_update" {
				continue
			}

			// Create certificate event
			timestamp := time.Unix(int64(cert.Data.Seen), 0)
			certType := "NEW"
			if time.Unix(int64(cert.Data.LeafCert.NotBefore), 0).Add(24 * time.Hour).Before(time.Now()) {
				certType = "RENEWAL"
			}

			event := CertEvent{
				Certificate: cert,
				Timestamp:   timestamp,
				CertType:    certType,
			}

			// If no domains specified, send all certificates
			if len(m.config.Domains) == 0 {
				select {
				case m.eventsChan <- event:
					// Event sent successfully
				default:
					// Channel is full, skip the event
					m.logger.Debug("Event channel full, skipping event")
				}
				continue
			}

			// Filter by specified domains
			var matchedDomains []string
			for _, watchDomain := range m.config.Domains {
				for _, certDomain := range cert.Data.LeafCert.AllDomains {
					if IsDomainMatch(certDomain, watchDomain) {
						matchedDomains = append(matchedDomains, watchDomain)
						break
					}
				}
			}

			// Send event if we have matched domains
			if len(matchedDomains) > 0 {
				event.MatchedDomains = matchedDomains
				select {
				case m.eventsChan <- event:
					// Event sent successfully
				default:
					// Channel is full, skip the event
					m.logger.Debug("Event channel full, skipping event")
				}
			}
		}
	}
}

// GetCertificateFromFile loads a certificate from a JSON file
func GetCertificateFromFile(path string) (*CertData, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cert CertData
	if err := json.Unmarshal(data, &cert); err != nil {
		return nil, err
	}

	return &cert, nil
}
