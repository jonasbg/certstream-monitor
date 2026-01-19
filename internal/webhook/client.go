// Package webhook provides HTTP client functionality for sending webhook notifications
package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/jonasbg/certstream-monitor/certstream"
)

// Client sends webhook notifications for certificate events
type Client struct {
	url        string
	apiToken   string
	timeout    time.Duration
	userAgent  string
	httpClient *http.Client
}

// NewClient creates a new webhook client
func NewClient(url, apiToken string) *Client {
	timeout := 10 * time.Second
	return &Client{
		url:       url,
		apiToken:  apiToken,
		timeout:   timeout,
		userAgent: "certstream-monitor/1.0",
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}
}

// Payload represents the data sent to the webhook endpoint
type Payload struct {
	Domain      string    `json:"domain"`
	Timestamp   time.Time `json:"timestamp"`
	CertType    string    `json:"cert_type"`
	CommonName  string    `json:"common_name"`
	Issuer      string    `json:"issuer"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	AllDomains  []string  `json:"all_domains"`
	MatchedWith string    `json:"matched_with"`
}

// Send sends a certificate event to the configured webhook endpoint
func (c *Client) Send(ctx context.Context, event certstream.CertEvent, matchedDomain string) error {
	if c.url == "" {
		return nil // No webhook configured
	}

	payload := c.buildPayload(event, matchedDomain)

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal webhook payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create webhook request: %w", err)
	}

	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send webhook request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned non-success status: %d", resp.StatusCode)
	}

	return nil
}

// buildPayload constructs the webhook payload from a certificate event
func (c *Client) buildPayload(event certstream.CertEvent, matchedDomain string) Payload {
	return Payload{
		Domain:      matchedDomain,
		Timestamp:   event.Timestamp,
		CertType:    event.CertType,
		CommonName:  event.Certificate.Data.LeafCert.Subject.CN,
		Issuer:      event.Certificate.Data.LeafCert.Issuer.O,
		NotBefore:   time.Unix(int64(event.Certificate.Data.LeafCert.NotBefore), 0),
		NotAfter:    time.Unix(int64(event.Certificate.Data.LeafCert.NotAfter), 0),
		AllDomains:  event.Certificate.Data.LeafCert.AllDomains,
		MatchedWith: matchedDomain,
	}
}

// setHeaders sets the required HTTP headers for the webhook request
func (c *Client) setHeaders(req *http.Request) {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	if c.apiToken != "" {
		req.Header.Set("x-api-token", c.apiToken)
	}
}

// SetTimeout sets the HTTP client timeout
func (c *Client) SetTimeout(timeout time.Duration) {
	c.timeout = timeout
	if c.httpClient != nil {
		c.httpClient.Timeout = timeout
	}
}

// SetUserAgent sets the User-Agent header
func (c *Client) SetUserAgent(userAgent string) {
	c.userAgent = userAgent
}
