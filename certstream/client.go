package certstream

import (
	"context"
	"encoding/json"
	"math"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
)

// Monitor is the certstream client that monitors certificate transparency logs
type Monitor struct {
	config            Config
	eventsChan        chan CertEvent
	rawMessageChan    chan []byte
	stopChan          chan struct{}
	logger            Logger
	wg                sync.WaitGroup
	mu                sync.Mutex
	isRunning         bool
	reconnectAttempts int
	droppedMessages   uint64 // Counter for dropped messages
}

// New creates a new certificate monitor with the given options
func New(options ...Option) *Monitor {
	// Initialize random seed for backoff calculations
	rand.Seed(time.Now().UnixNano())

	config := Config{
		WebSocketURL:        DefaultWebSocketURL,
		Domains:             []string{},
		Debug:               false,
		ReconnectTimeout:    time.Second,
		MaxReconnectTimeout: 5 * time.Minute,
		BufferSize:          50000,
		WorkerCount:         4,
		Context:             context.Background(),
	}

	for _, option := range options {
		option(&config)
	}

	// Ensure reasonable defaults
	if config.BufferSize < 100 {
		config.BufferSize = 50000
	}
	if config.WorkerCount < 1 {
		config.WorkerCount = 4
	}

	return &Monitor{
		config:            config,
		eventsChan:        make(chan CertEvent, config.BufferSize),
		rawMessageChan:    make(chan []byte, config.BufferSize*3),
		stopChan:          make(chan struct{}),
		logger:            NewDefaultLogger(config.Debug),
		reconnectAttempts: 0,
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

	// Start worker pool for processing messages
	for i := 0; i < m.config.WorkerCount; i++ {
		m.wg.Add(1)
		go m.processWorker()
	}

	// Start main monitor goroutine
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
			if success := m.connectAndProcess(ctx); success {
				// Reset reconnect attempts on successful connection
				m.reconnectAttempts = 0
			} else {
				// Increment reconnect attempts
				m.reconnectAttempts++
			}

			// Check if we should exit
			select {
			case <-ctx.Done():
				return
			case <-m.stopChan:
				return
			default:
				// Calculate backoff with exponential increase
				backoff := m.calculateBackoff()
				if backoff == 0 {
					m.logger.Info("Connection lost. Reconnecting immediately...")
				} else {
					m.logger.Info("Connection lost. Reconnecting in %v...", backoff)
				}

				// Use a timer so we can be interrupted by stop signal
				timer := time.NewTimer(backoff)
				select {
				case <-timer.C:
					// Backoff completed, continue to reconnect
				case <-ctx.Done():
					timer.Stop()
					return
				case <-m.stopChan:
					timer.Stop()
					return
				}
			}
		}
	}
}

// calculateBackoff computes the backoff duration using exponential strategy
func (m *Monitor) calculateBackoff() time.Duration {
	// If backoff is disabled, reconnect immediately
	if m.config.DisableBackoff {
		return 0
	}

	backoffSeconds := float64(m.config.ReconnectTimeout) / float64(time.Second)
	maxBackoffSeconds := float64(m.config.MaxReconnectTimeout) / float64(time.Second)

	// Calculate exponential backoff with a small random jitter
	jitter := 0.1 + 0.2*rand.Float64() // 10-30% jitter
	calculatedBackoff := backoffSeconds * math.Pow(2, float64(m.reconnectAttempts)) * (1 + jitter)

	// Cap at maximum timeout
	if calculatedBackoff > maxBackoffSeconds {
		calculatedBackoff = maxBackoffSeconds
	}

	return time.Duration(calculatedBackoff) * time.Second
}

// connectAndProcess establishes the websocket connection and processes incoming certificates
func (m *Monitor) connectAndProcess(ctx context.Context) bool {
	m.logger.Debug("Connecting to %s", m.config.WebSocketURL)

	conn, _, err := websocket.Dial(ctx, m.config.WebSocketURL, nil)
	if err != nil {
		m.logger.Error("Connection error: %v", err)
		return false
	}
	defer conn.Close(websocket.StatusAbnormalClosure, "")

	// Set message read limit to 100MB to handle large certificate messages with full chains
	conn.SetReadLimit(100 * 1024 * 1024)

	m.logger.Debug("Connected to CertStream service")

	// Start ping goroutine
	pingCtx, pingCancel := context.WithCancel(ctx)
	defer pingCancel()

	go m.pingLoop(pingCtx, conn)

	return m.processMessages(ctx, conn)
}

// pingLoop sends periodic pings to keep the connection alive
func (m *Monitor) pingLoop(ctx context.Context, conn *websocket.Conn) {
	ticker := time.NewTicker(25 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := conn.Ping(ctx); err != nil {
				m.logger.Debug("Ping failed: %v", err)
				return
			}
			m.logger.Debug("Sent ping to server")
		}
	}
}

// processMessages reads certificate messages from the WebSocket and queues them for processing
func (m *Monitor) processMessages(ctx context.Context, conn *websocket.Conn) bool {
	for {
		select {
		case <-ctx.Done():
			conn.Close(websocket.StatusNormalClosure, "")
			return true
		case <-m.stopChan:
			conn.Close(websocket.StatusNormalClosure, "")
			return true
		default:
			_, data, err := conn.Read(ctx)
			if err != nil {
				m.logger.Error("Read error: %v", err)
				return false
			}

			// Queue message for processing without blocking
			select {
			case m.rawMessageChan <- data:
				// Successfully queued
			default:
				// Buffer full, drop message (should rarely happen with large buffer)
				dropped := atomic.AddUint64(&m.droppedMessages, 1)
				if dropped%1000 == 0 {
					m.logger.Error("Dropped %d messages due to processing backlog", dropped)
				}
			}
		}
	}
}

// processWorker processes messages from the raw message channel
func (m *Monitor) processWorker() {
	defer m.wg.Done()

	for {
		select {
		case <-m.stopChan:
			return
		case data, ok := <-m.rawMessageChan:
			if !ok {
				return
			}
			m.processCertificate(data)
		}
	}
}

// processCertificate parses and handles a certificate message
func (m *Monitor) processCertificate(data []byte) {
	type certMessageLite struct {
		MessageType string `json:"message_type"`
		Data        struct {
			LeafCert struct {
				AllDomains []string `json:"all_domains"`
			} `json:"leaf_cert"`
		} `json:"data"`
	}

	var lite certMessageLite
	if err := json.Unmarshal(data, &lite); err != nil {
		m.logger.Error("JSON error: %v", err)
		return
	}

	if lite.MessageType != "certificate_update" {
		return
	}

	// If no domains specified, we need the full payload for output.
	if len(m.config.Domains) == 0 {
		var cert CertData
		if err := json.Unmarshal(data, &cert); err != nil {
			m.logger.Error("JSON error: %v", err)
			return
		}
		event := m.createCertEvent(cert)
		m.sendEvent(event)
		return
	}

	// Filter by specified domains using the lightweight decode first.
	matchedDomains := m.findMatchedDomainsFromList(lite.Data.LeafCert.AllDomains)
	if len(matchedDomains) == 0 {
		return
	}

	var cert CertData
	if err := json.Unmarshal(data, &cert); err != nil {
		m.logger.Error("JSON error: %v", err)
		return
	}

	event := m.createCertEvent(cert)
	event.MatchedDomains = matchedDomains
	m.sendEvent(event)
}

// createCertEvent creates a CertEvent from certificate data
func (m *Monitor) createCertEvent(cert CertData) CertEvent {
	timestamp := time.Unix(int64(cert.Data.Seen), 0)
	certType := "NEW"
	if time.Unix(int64(cert.Data.LeafCert.NotBefore), 0).Add(24 * time.Hour).Before(time.Now()) {
		certType = "RENEWAL"
	}

	return CertEvent{
		Certificate: cert,
		Timestamp:   timestamp,
		CertType:    certType,
	}
}

// findMatchedDomains returns domains that match the configured watch list
func (m *Monitor) findMatchedDomains(cert CertData) []string {
	var matchedDomains []string
	for _, watchDomain := range m.config.Domains {
		for _, certDomain := range cert.Data.LeafCert.AllDomains {
			if IsDomainMatch(certDomain, watchDomain) {
				matchedDomains = append(matchedDomains, watchDomain)
				break
			}
		}
	}
	return matchedDomains
}

func (m *Monitor) findMatchedDomainsFromList(domains []string) []string {
	var matchedDomains []string
	for _, watchDomain := range m.config.Domains {
		for _, certDomain := range domains {
			if IsDomainMatch(certDomain, watchDomain) {
				matchedDomains = append(matchedDomains, watchDomain)
				break
			}
		}
	}
	return matchedDomains
}

// sendEvent sends an event to the events channel
func (m *Monitor) sendEvent(event CertEvent) {
	select {
	case m.eventsChan <- event:
		// Event sent successfully
	default:
		// Channel is full, skip the event (consumer is too slow)
		if m.config.Debug {
			m.logger.Debug("Event channel full, consumer too slow")
		}
	}
}
