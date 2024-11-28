package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/coder/websocket"
)

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

// ANSI color codes
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorPurple = "\033[35m"
	colorCyan   = "\033[36m"
	colorWhite  = "\033[37m"
)

// Config holds the configuration for the certificate monitor
type Config struct {
	WebSocketURL string
	Domains      []string
	Verbose      bool
}

func DefaultConfig() Config {
	return Config{
		WebSocketURL: "wss://certstream.calidog.io/",
		Domains:      []string{},
		Verbose:      false,
	}
}

// logVerbose prints message only in verbose mode
func logVerbose(config Config, format string, a ...interface{}) {
	if config.Verbose {
		fmt.Printf(format+"\n", a...)
	}
}

// logError prints error messages in red
func logError(format string, a ...interface{}) {
	fmt.Printf(colorRed+format+colorReset+"\n", a...)
}

func monitorCertStream(config Config, done chan bool) {
	ctx := context.Background()

	for {
		conn, _, err := websocket.Dial(ctx, config.WebSocketURL, nil)
		if err != nil {
			logError("Connection error: %v", err)
			logVerbose(config, "Retrying connection in 1 second...")
			time.Sleep(time.Second)
			continue
		}

		streamClosed := false
		for !streamClosed {
			select {
			case <-done:
				conn.Close(websocket.StatusNormalClosure, "")
				return

			default:
				_, data, err := conn.Read(ctx)
				if err != nil {
					logError("Read error: %v", err)
					streamClosed = true
					conn.Close(websocket.StatusAbnormalClosure, "")
					continue
				}

				var cert CertData
				if err := json.Unmarshal(data, &cert); err != nil {
					logError("JSON error: %v", err)
					continue
				}

				if cert.MessageType != "certificate_update" {
					continue
				}

				timestamp := time.Unix(int64(cert.Data.Seen), 0).Format("2006-01-02T15:04:05")

				// If no domains specified, print all certificates
				if len(config.Domains) == 0 {
					if config.Verbose {
						certType := "NEW"
						if time.Unix(int64(cert.Data.LeafCert.NotBefore), 0).Add(24 * time.Hour).Before(time.Now()) {
							certType = "RENEWAL"
						}

						fmt.Printf("[%s] ", timestamp)
						fmt.Printf(colorYellow+"%s"+colorReset, cert.Data.Source.URL)
						fmt.Printf(" - ")
						fmt.Printf(colorGreen+"%s"+colorReset, cert.Data.LeafCert.Subject.CN)
						fmt.Printf("\n    Type: %s", certType)
						fmt.Printf("\n    Issuer: %s", cert.Data.LeafCert.Issuer.O)
						fmt.Printf("\n    Valid: %s -> %s\n",
							time.Unix(int64(cert.Data.LeafCert.NotBefore), 0).Format("2006-01-02"),
							time.Unix(int64(cert.Data.LeafCert.NotAfter), 0).Format("2006-01-02"))
					} else {
						fmt.Printf("[%s] ", timestamp)
						fmt.Printf(colorYellow+"%s"+colorReset, cert.Data.Source.URL)
						fmt.Printf(" - ")
						fmt.Printf(colorGreen+"%s\n"+colorReset, cert.Data.LeafCert.Subject.CN)
					}
					continue
				}

				// Filter by specified domains
				for _, watchDomain := range config.Domains {
					for _, certDomain := range cert.Data.LeafCert.AllDomains {
						if strings.Contains(strings.ToLower(certDomain), strings.ToLower(watchDomain)) {
							certType := "NEW"
							if time.Unix(int64(cert.Data.LeafCert.NotBefore), 0).Add(24 * time.Hour).Before(time.Now()) {
								certType = "RENEWAL"
							}

							if config.Verbose {
								fmt.Printf("[%s] ", timestamp)
								fmt.Printf(colorYellow+"%s"+colorReset, cert.Data.Source.URL)
								fmt.Printf(" - ")
								fmt.Printf(colorGreen+"%s"+colorReset, cert.Data.LeafCert.Subject.CN)
								fmt.Printf(colorYellow+" (matched: %s)"+colorReset, watchDomain)
								fmt.Printf("\n    Type: %s", certType)
								fmt.Printf("\n    Issuer: %s", cert.Data.LeafCert.Issuer.O)
								fmt.Printf("\n    Valid: %s -> %s\n",
									time.Unix(int64(cert.Data.LeafCert.NotBefore), 0).Format("2006-01-02"),
									time.Unix(int64(cert.Data.LeafCert.NotAfter), 0).Format("2006-01-02"))
							} else {
								fmt.Printf("[%s] ", timestamp)
								fmt.Printf(colorYellow+"%s"+colorReset, cert.Data.Source.URL)
								fmt.Printf(" - ")
								fmt.Printf(colorGreen+"%s\n"+colorReset, cert.Data.LeafCert.Subject.CN)
							}
							break
						}
					}
				}
			}
		}

		logVerbose(config, "Connection lost. Reconnecting in 1 second...")
		time.Sleep(time.Second)
	}
}

func main() {
	verbose := flag.Bool("v", false, "Enable verbose output")
	veryVerbose := flag.Bool("verbose", false, "Enable verbose output")
	flag.Parse()

	// Create configuration with default values
	config := DefaultConfig()
	config.Verbose = *verbose || *veryVerbose

	// Get remaining arguments after flags as domains
	args := flag.Args()
	if len(args) > 0 {
		config.Domains = args
		if config.Verbose {
			fmt.Printf(colorCyan+"Starting monitoring for domains: %v\n"+colorReset, config.Domains)
		}
	} else if config.Verbose {
		fmt.Println(colorCyan + "No domains specified. Monitoring all certificates." + colorReset)
	}

	// Allow override of WebSocket URL through environment variable
	if wsURL := os.Getenv("CERTSTREAM_URL"); wsURL != "" {
		config.WebSocketURL = wsURL
	}

	if config.Verbose {
		fmt.Printf(colorCyan+"Using CertStream URL: %s\n"+colorReset, config.WebSocketURL)
		fmt.Println(colorCyan + "Waiting for certificates... (Press CTRL+C to exit)" + colorReset)
	}

	done := make(chan bool)
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		<-c
		if config.Verbose {
			fmt.Println("\nShutting down...")
		}
		done <- true
	}()

	monitorCertStream(config, done)
}
