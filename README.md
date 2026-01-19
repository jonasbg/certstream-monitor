# CertStream Monitor

Real-time SSL/TLS certificate monitoring tool using CertStream.

## Features

- Monitor multiple domains with exact matching
- Auto-reconnection with exponential backoff
- Real-time certificate detection
- Tracks both new and renewal certificates
- Webhook notifications for matched domains
- API token authentication support
- WebSocket ping/pong keepalive
- Configurable WebSocket endpoint
- Usable as a standalone tool or importable module

## Quick Start

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
./certstream-monitor -v

# High-volume monitoring with performance tuning
NO_BACKOFF=true \
BUFFER_SIZE=50000 \
WORKERS=8 \
./certstream-monitor -v nhn.no

# Or using flags
./certstream-monitor --no-backoff --buffer-size 50000 --workers 8 nhn.no
```

## Configuration

### Command Line Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-v` or `--verbose` | Enable verbose output | `false` |
| `--urls-only` | Output only URLs | `false` |
| `--reconnect-timeout` | Base reconnection timeout in seconds | `1` |
| `--max-reconnect` | Maximum reconnection timeout in seconds | `300` || `--no-backoff` | Disable exponential backoff (reconnect immediately) | `false` |
| `--buffer-size` | Internal event buffer size for high-volume streams | `10000` |
| `--workers` | Number of parallel workers for processing messages | `4` |
### Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `TARGET_DOMAINS` | Comma or space-separated list of domains to monitor | `nhn.no example.com` |
| `WEBHOOK_URL` | Target API endpoint for webhook notifications | `https://api.example.com/webhook` |
| `API_TOKEN` | Authentication token for webhook (optional) | `your-secret-token` |
| `CERTSTREAM_URL` | Custom CertStream WebSocket URL (optional) | `wss://certstream.calidog.io/` || `NO_BACKOFF` | Disable exponential backoff for reconnections | `true` or `1` |
| `BUFFER_SIZE` | Internal event buffer size (increase for high volume) | `50000` |
| `WORKERS` | Number of parallel workers for message processing | `8` |
**Note:** Command-line arguments override the `TARGET_DOMAINS` environment variable.

### Performance Tuning

For high-volume certificate streams (thousands of certificates per second), you can tune the following parameters:

- **Buffer Size** (`--buffer-size` or `BUFFER_SIZE`): Increase the internal event buffer to handle bursts of certificates. Default is 10,000. For high-volume streams, try 50,000 or higher.

- **Worker Count** (`--workers` or `WORKERS`): Number of parallel goroutines processing messages. Default is 4. Increase to 8 or 16 for better throughput on multi-core systems.

- **No Backoff** (`--no-backoff` or `NO_BACKOFF`): Disables exponential backoff for reconnections. When enabled, the monitor reconnects immediately after disconnection instead of waiting with increasing delays.

```bash
# Example: High-performance configuration
NO_BACKOFF=true BUFFER_SIZE=50000 WORKERS=8 ./certstream-monitor nhn.no
```

### Domain Matching

The monitor uses exact domain matching to prevent false positives:
- `nhn.no` matches `nhn.no` and `www.nhn.no`
- `nhn.no` does NOT match `mynhn.no` or `nhn.no.example.com`

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

#### Webhook Payload Fields

| Field | Type | Description |
|-------|------|-------------|
| `domain` | string | The specific domain that matched your monitored domain |
| `timestamp` | string (ISO 8601) | When the certificate was seen in the transparency log |
| `cert_type` | string | Either "NEW" (new certificate) or "RENEWAL" (renewed certificate) |
| `common_name` | string | The Common Name (CN) from the certificate's subject |
| `issuer` | string | The organization (O) that issued the certificate |
| `not_before` | string (ISO 8601) | Certificate validity start date/time |
| `not_after` | string (ISO 8601) | Certificate validity end date/time |
| `all_domains` | array of strings | All domains included in the certificate (SAN entries) |
| `matched_with` | string | The domain from your watch list that triggered this match |

#### Webhook Request Headers

The webhook request includes the following headers:
- `Content-Type: application/json` - Indicates JSON payload
- `User-Agent: certstream-monitor/1.0` - Identifies the client application
- `x-api-token: <your-token>` - Authentication token (only included if `API_TOKEN` is set)

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

## Using as a Module

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
- `WithDebug(bool)` - Enable debug logging
- `WithReconnectTimeout(time.Duration)` - Set base timeout for reconnection attempts
- `WithMaxReconnectTimeout(time.Duration)` - Set maximum reconnection timeout
- `WithDisableBackoff(bool)` - Disable exponential backoff for immediate reconnection
- `WithBufferSize(int)` - Set internal event buffer size (default: 10000)
- `WithWorkerCount(int)` - Set number of parallel processing workers (default: 4)
- `WithContext(context.Context)` - Set a context to control the monitor lifecycle

### Methods

- `monitor.Start()` - Start the monitoring process
- `monitor.Stop()` - Stop the monitoring process gracefully
- `monitor.Events()` - Returns a read-only channel of certificate events
- `monitor.SetLogger(logger)` - Set a custom logger implementation

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

## Command Line Usage Examples

Monitor multiple domains:
```bash
./certstream-monitor example.com subdomain.example.com another.com
```

Monitor domains from environment variable:
```bash
TARGET_DOMAINS="nhn.no example.com" ./certstream-monitor
```

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

### Troubleshooting Connection Issues

- **404 error?** Check the endpoint path - try `/`, `/full-stream`, or `/domains-only`
- **Connection refused?** Verify the server is running on the specified port
- **Random disconnects?** This monitor sends pings every 25s as required by certstream-server-go

## Build

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

## Testing

Run all tests:
```bash
go test ./...
```

Run with coverage:
```bash
go test -cover ./...
```

Run vet and tests:
```bash
go vet ./... && go test ./...
```

## Project Structure

```
certstream-monitor/
├── cmd/cli/                  # CLI application entry point
│   └── main.go
├── certstream/               # Core monitoring logic
│   ├── client.go            # WebSocket client & monitor
│   ├── types.go             # Data structures & options
│   ├── logger.go            # Logging interface
│   ├── matcher.go           # Domain matching logic
│   └── util.go              # Utility functions
├── internal/                 # Private implementation packages
│   ├── config/              # Configuration management
│   ├── output/              # Output formatting
│   └── webhook/             # Webhook notifications
└── go.mod
```

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

### How to Contribute

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development

```bash
# Clone the repository
git clone https://github.com/jonasbg/certstream-monitor.git
cd certstream-monitor

# Install dependencies
go mod download

# Run tests
go test ./...

# Build
go build -o certstream-monitor ./cmd/cli
```

## Support

If you encounter any issues or have questions:
- Open an issue on GitHub
- Check existing issues for solutions
- Review the troubleshooting section above
