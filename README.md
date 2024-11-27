# 🔍 CertStream Monitor

Real-time SSL/TLS certificate monitoring tool using CertStream! 🚀

## 🌟 Features

- 🎯 Monitor multiple domains
- 🔄 Auto-reconnection
- ⚡ Real-time certificate detection
- 🔐 Tracks both new and renewal certificates
- 🛠️ Configurable WebSocket endpoint

## 🚀 Quick Start

```bash
# Install
go get github.com/jonasbg/certstream-monitor

# Run with default settings
./certstream-monitor example.com

# Run with custom CertStream server
CERTSTREAM_URL=ws://your-server:8080/stream ./certstream-monitor example.com
```

## 💻 Code Example

```go
package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	certmonitor "github.com/jonasbg/certstream-monitor"
)

func main() {
	// Domains to monitor
	domains := []string{"example.com", "yourdomain.com"}
	
	// Create a done channel for shutdown
	done := make(chan bool)
	
	// Set up graceful shutdown
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
		<-sigChan
		fmt.Println("\nShutting down...")
		done <- true
	}()

	// Initialize and start the monitor
	monitor := certmonitor.New(
		certmonitor.WithDomains(domains),
		certmonitor.WithWebSocketURL("ws://localhost:8080/full-stream"),
	)

	// Start monitoring with callback for certificate events
	monitor.Start(done, func(cert *certmonitor.CertData) {
		// Handle certificate updates here
		fmt.Printf("Certificate update for: %s\n", cert.Data.LeafCert.Subject.CN)
	})
}
```

## 🎮 Usage Examples

Monitor multiple domains:
```bash
./certstream-monitor example.com subdomain.example.com another.com
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
