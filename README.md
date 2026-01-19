# 🔍 CertStream Monitor

Real-time SSL/TLS certificate monitoring tool using CertStream! 🚀

## 🌟 Features

- 🎯 Monitor multiple domains with exact matching
- 🔄 Auto-reconnection with exponential backoff
- ⚡ Real-time certificate detection
- 🔐 Tracks both new and renewal certificates
- 🌐 Webhook notifications for matched domains
- 🔒 API token authentication support
- 💓 WebSocket ping/pong keepalive
- 🛠️ Configurable WebSocket endpoint
- 📦 Usable as a standalone tool or importable module

## 🚀 Quick Start

```bash
# Install
go get github.com/jonasbg/certstream-monitor

# Monitor domains from command line
./certstream-monitor nhn.no example.com

# Monitor domains from environment variable
TARGET_DOMAINS="nhn.no example.com" ./certstream-monitor

# Use custom CertStream server
CERTSTREAM_URL="wss://your-certstream-server.com/" ./certstream-monitor nhn.no

# With webhook notifications
TARGET_DOMAINS="nhn.no" \
WEBHOOK_URL="https://your-api.com/webhook" \
API_TOKEN="your-secret-token" \
./certstream-monitor

# Full configuration example
TARGET_DOMAINS="nhn.no example.com" \
CERTSTREAM_URL="wss://certstream.calidog.io/" \
WEBHOOK_URL="https://your-api.com/webhook" \
API_TOKEN="your-secret-token" \
./cCERTSTREAM_URL` | **Custom CertStream WebSocket URL** (optional, defaults to official server) | `wss://your-server.com/` |
| `WEBHOOK_URL` | Target API endpoint for webhook notifications | `https://api.example.com/webhook` |
| `API_TOKEN` | Authentication token for webhook (optional) | `your-secret-token` |

**Notes:**
- Command-line arguments override the `TARGET_DOMAINS` environment variable
- `CERTSTREAM_URL` is critical for using self-hosted or alternative CertStream servers
- Default CertStream URL: `wss://certstream.calidog.io/`
### Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `TARGET_DOMAINS` | Comma or space-separated list of domains to monitor | `nhn.no example.com` |
| `WEBHOOK_URL` | Target API endpoint for webhook notifications | `https://api.example.com/webhook` |
| `API_TOKEN` | Authentication token for webhook (optional) | `your-secret-token` |
| `CERTSTREAM_URL` | Custom CertStream WebSocket URL (optional) | `wss://certstream.calidog.io/` |

**Note:** Command-line arguments override the `TARGET_DOMAINS` environment variable.

### Domain Matching

The monitor uses exact domain matching to prevent false positives:
- ✅ `nhn.no` matches `nhn.no` and `www.nhn.no`
- ❌ `nhn.no` does NOT match `mynhn.no` or `nhn.no.example.com`

**Note:** If no domains are specified via `TARGET_DOMAINS` or command-line arguments, the monitor will stream ALL certificates from the CertStream server.

### Webhook Notifications

When a matching domain is found, the monitor sends a POST request to the configured webhook URL with the following JSON payload:

```json
{
  "domain": "www.nhn.no",
  "timestamp": "2026-01-19T10:30:45Z",
  "cert_type": "NEW",
  "common_name": "www.nhn.no",
  "issuer": "Let's Encrypt",
  "not_before": "2026-01-19T00:00:00Z",
  "not_after": "2026-04-19T00:00:00Z",
  "all_domains": ["nhn.no", "www.nhn.no"],
  "matched_with": "nhn.no"
}
```

The webhook request includes:
- `Content-Type: application/json` header
- `x-api-token: <your-token>` header (if `API_TOKEN` is set)

### WebSocket Keepalive

The monitor automatically sends ping frames every 25 seconds to keep the WebSocket connection alive and detect disconnections early.

**Important:** The client (this monitor) sends pings to the server. Most certstream servers (like certstream-server-go) require clients to send pings at least every 60 seconds (recommended 30s interval). The 25-second interval ensures compliance with these requirements.

### CertStream Server Endpoints

If you're running a custom certstream-server-go instance, it offers multiple endpoints:

| Endpoint | Description | Use Case |
|----------|-------------|----------|
| `/full-stream` | Full certificate details (includes `as_der` and `chain` fields) | Complete certificate information |
| `/` | Lite stream with reduced details (no `as_der` and `chain`) | Most common, lower bandwidth |
| `/domains-only` | Only domain names from certificates | Minimal bandwidth, domain monitoring |

Examples:
```bash
# Connect to full-stream endpoint
CERTSTREAM_URL="ws://localhost:9999/full-stream" ./certstream-monitor nhn.no

# Connect to lite stream (root endpoint)
CERTSTREAM_URL="ws://localhost:9999/" ./certstream-monitor nhn.no

# Connect to domains-only stream
CERTSTREAM_URL="ws://localhost:9999/domains-only" ./certstream-monitor nhn.no
```

## 💻 Using as a Module

```go
package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jonasbg/certstream-monitor/certstream"
)

func main() {
	// Create a monitor with options
	monitor := certstream.New(
		certstream.WithDomains([]string{"example.com", "yourdomain.com"}),
		certstream.WithDebug(true),
		certstream.WithWebSocketURL("wss://certstream.calidog.io/"),
		certstream.WithReconnectTimeout(time.Second * 3),
		certstream.WithWebhookURL("https://your-api.com/webhook"),
		certstream.WithAPIToken("your-secret-token"),
	)

	// Start monitoring
	monitor.Start()

	// Setup signal handling for clean shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Process certificate events
	for {
		select {
		case event := <-monitor.Events():
			// Process the certificate event
			fmt.Printf("Certificate for: %s (Type: %s)\n", 
				event.Certificate.Data.LeafCert.Subject.CN,
				event.CertType)

		case <-sigChan:
			// Graceful shutdown
			fmt.Println("Shutting down...")
			monitor.Stop()
			return
		}
	}
}
```

### Available Options

When creating a new monitor with `certstream.New()`, you can provide these options:

- `WithDomains([]string)` - Set domains to monitor
- `WithWebSocketURL(string)` - Set custom CertStream WebSocket URL
- `WithWebhookURL(string)` - Set webhook URL for notifications
- `WithAPIToken(string)` - Set API token for webhook authentication
- `WithDebug(bool)` - Enable debug logging
- `WithReconnectTimeout(time.Duration)` - Set base timeout for reconnection attempts
- `WithMaxReconnectTimeout(time.Duration)` - Set maximum reconnection timeout
- `WithContext(context.Context)` - Set a context to control the monitor lifecycle

### Methods

- `monitor.Start()` - Start the monitoring process
- `monitor.Stop()` - Stop the monitoring process gracefully
- `monitor.Events()` - Returns a read-only channel of certificate events

### Custom Logger

```go
// Implement the Logger interface
type MyLogger struct {
    // Your fields here
}

func (l *MyLogger) Debug(format string, v ...interface{}) {
    // Your debug logging implementation
}

func (l *MyLogger) Info(format string, v ...interface{}) {
    // Your info logging implementation
}

func (l *MyLogger) Error(format string, v ...interface{}) {
    // Your error logging implementation
}

// Set the logger
monitor.SetLogger(&MyLogger{})
```

## 🎮 Command Line Usage Examples

Monitor multiple domains:
```bash
./certstream-monitor example.com subdomain.example.com another.com
```

Monitor domains from environment variable:
```bash
Use custom CertStream server:
```bash
CERTSTREAM_URL="wss://your-certstream-server.com/" ./certstream-monitor nhn.no
```

Enable verbose output:
```bash
./certstream-monitor -v example.com
```

Show only domain names in output:
```bash
./certstream-monitor --urls-only example.com
```

Full example with webhook and custom server:
```bash
TARGET_DOMAINS="nhn.no" \
CERTSTREAM_URL="wss://certstream.calidog.io/" \
WEBHOOK_URL="https://api.example.com/webhook" \
API_TOKEN="secret-token-123" \
./certstream-monitor -v
```

Testing with local CertStream server:
```bash
# Test connection without filtering (streams all certificates)
CERTSTREAM_URL="ws://localhost:9999/" ./certstream-monitor -v

# With domain filtering on lite endpoint
CERTSTREAM_URL="ws://localhost:9999/" \
TARGET_DOMAINS="test.com" \
./certstream-monitor -v

# With full-stream endpoint
CERTSTREAM_URL="ws://localhost:9999/full-stream" \
TARGET_DOMAINS="test.com" \
./certstream-monitor -v
```

**Troubleshooting connection issues:**
- **404 error?** Check the endpoint path - try `/`, `/full-stream`, or `/domains-only`
- **Connection refused?** Verify the server is running on the specified port
- **Random disconnects?** This monitor sends pings every 25s as required by certstream-server-go

## 🔧 Build

Build for your platform:
```bash
go build -o certstream-monitor ./cmd/cli
```

Build with optimizations (static binary):
```bash
CGO_ENABLED=0 go build -ldflags "-s -w" -trimpath -o certstream-monitor ./cmd/cli
```

Cross-compile for macOS ARM64:
```bash
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags "-s -w" -trimpath -o certstream-monitor ./cmd/cli
```

Cross-compile for Linux:
```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -trimpath -o certstream-monitor ./cmd/cli
```

## 📜 License

MIT License 🎉

## 🤝 Contributing

PRs welcome! 🎈
