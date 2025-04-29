# 🔍 CertStream Monitor

Real-time SSL/TLS certificate monitoring tool using CertStream! 🚀

## 🌟 Features

- 🎯 Monitor multiple domains
- 🔄 Auto-reconnection
- ⚡ Real-time certificate detection
- 🔐 Tracks both new and renewal certificates
- 🛠️ Configurable WebSocket endpoint
- 📦 Usable as a standalone tool or importable module

## 🚀 Quick Start

```bash
# Install
go get github.com/jonasbg/certstream-monitor

# Run with default settings
./certstream-monitor example.com

# Run with custom CertStream server
CERTSTREAM_URL=ws://your-server:8080/stream ./certstream-monitor example.com
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
- `WithReconnectTimeout(time.Duration)` - Set timeout for reconnection attempts
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

Enable verbose output:
```bash
./certstream-monitor -v example.com
```

Show only domain names in output:
```bash
./certstream-monitor --urls-only example.com
```

## 🔧 Configuration

Set custom WebSocket URL:
```bash
export CERTSTREAM_URL=ws://your-custom-server:8080/stream
```

## 🧱 BUILD

```go
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags "-s -w" -trimpath -o certstream-monitor main.go
```

## 📜 License

MIT License 🎉

## 🤝 Contributing

PRs welcome! 🎈
