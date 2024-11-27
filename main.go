package main

import (
	"context"
	"encoding/json"
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

func monitorCertStream(domains []string, done chan bool) {
	ctx := context.Background()

	for {
		conn, _, err := websocket.Dial(ctx, "ws://192.168.1.240:8080/full-stream", nil)
		if err != nil {
			fmt.Printf("Connection error: %v\n", err)
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
					fmt.Printf("Read error: %v\n", err)
					streamClosed = true
					conn.Close(websocket.StatusAbnormalClosure, "")
					continue
				}

				var cert CertData
				if err := json.Unmarshal(data, &cert); err != nil {
					fmt.Printf("JSON error: %v\n", err)
					continue
				}

				if cert.MessageType != "certificate_update" {
					continue
				}

				for _, watchDomain := range domains {
					for _, certDomain := range cert.Data.LeafCert.AllDomains {
						if strings.Contains(strings.ToLower(certDomain), strings.ToLower(watchDomain)) {
							certTime := time.Unix(int64(cert.Data.LeafCert.NotBefore), 0)
							now := time.Now()
							certType := "NEW"
							if now.Sub(certTime).Hours() > 24 {
								certType = "RENEWAL"
							}

							fmt.Printf("\nCertificate %s for watched domain: %s\n", certType, watchDomain)
							fmt.Printf("Matching domain: %s\n", certDomain)
							fmt.Printf("Issuer: %s\n", cert.Data.LeafCert.Issuer.O)
							fmt.Printf("Subject CN: %s\n", cert.Data.LeafCert.Subject.CN)
							fmt.Printf("Source: %s (%s)\n", cert.Data.Source.Name, cert.Data.Source.URL)
							fmt.Printf("Validity: %s -> %s\n",
								time.Unix(int64(cert.Data.LeafCert.NotBefore), 0).Format(time.RFC3339),
								time.Unix(int64(cert.Data.LeafCert.NotAfter), 0).Format(time.RFC3339))
							fmt.Printf("Found at: %s\n", time.Unix(int64(cert.Data.Seen), 0).Format(time.RFC3339))
							fmt.Println(strings.Repeat("-", 50))
							break
						}
					}
				}
			}
		}

		fmt.Println("Connection lost. Reconnecting in 1 second...")
		time.Sleep(time.Second)
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: ./certstream-monitor domain1 [domain2 ...]")
		fmt.Println("Example: ./certstream-monitor example.com subdomain.example.com")
		os.Exit(1)
	}

	domains := os.Args[1:]
	fmt.Printf("Starting monitoring for domains: %v\n", domains)
	fmt.Println("Waiting for certificates... (Press CTRL+C to exit)")

	done := make(chan bool)
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		<-c
		fmt.Println("\nShutting down...")
		os.Exit(0) // Force exit if graceful shutdown fails
		done <- true
	}()

	monitorCertStream(domains, done)
}
