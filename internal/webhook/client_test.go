package webhook

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jonasbg/certstream-monitor/certstream"
)

func TestNewClient(t *testing.T) {
	client := NewClient("https://example.com/webhook", "token123")
	if client == nil {
		t.Fatal("expected non-nil client")
	}
	if client.url != "https://example.com/webhook" {
		t.Errorf("expected url to be set")
	}
	if client.apiToken != "token123" {
		t.Errorf("expected api token to be set")
	}
}

func TestClient_Send(t *testing.T) {
	// Create a test server
	receivedPayload := &Payload{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify headers
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected Content-Type header")
		}
		if r.Header.Get("x-api-token") != "test-token" {
			t.Errorf("expected x-api-token header")
		}

		// Decode payload
		if err := json.NewDecoder(r.Body).Decode(receivedPayload); err != nil {
			t.Errorf("failed to decode payload: %v", err)
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create client
	client := NewClient(server.URL, "test-token")

	// Create test event
	event := certstream.CertEvent{
		Certificate: certstream.CertData{},
		Timestamp:   time.Now(),
		CertType:    "NEW",
	}
	event.Certificate.Data.LeafCert.Subject.CN = "example.com"
	event.Certificate.Data.LeafCert.Issuer.O = "Let's Encrypt"
	event.Certificate.Data.LeafCert.AllDomains = []string{"example.com", "www.example.com"}
	event.Certificate.Data.LeafCert.NotBefore = float64(time.Now().Unix())
	event.Certificate.Data.LeafCert.NotAfter = float64(time.Now().Add(90 * 24 * time.Hour).Unix())

	// Send webhook
	ctx := context.Background()
	err := client.Send(ctx, event, "example.com")
	if err != nil {
		t.Fatalf("failed to send webhook: %v", err)
	}

	// Verify received payload
	if receivedPayload.Domain != "example.com" {
		t.Errorf("expected domain to be example.com, got %s", receivedPayload.Domain)
	}
	if receivedPayload.CertType != "NEW" {
		t.Errorf("expected cert type to be NEW, got %s", receivedPayload.CertType)
	}
}

func TestClient_Send_NoURL(t *testing.T) {
	// Client with no URL should not send
	client := NewClient("", "")
	event := certstream.CertEvent{}

	err := client.Send(context.Background(), event, "example.com")
	if err != nil {
		t.Errorf("expected no error when URL is empty, got %v", err)
	}
}

func TestClient_Send_ErrorResponse(t *testing.T) {
	// Create a test server that returns an error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := NewClient(server.URL, "")
	event := certstream.CertEvent{}

	err := client.Send(context.Background(), event, "example.com")
	if err == nil {
		t.Error("expected error for non-success status code")
	}
}

func TestClient_SetTimeout(t *testing.T) {
	client := NewClient("https://example.com", "")
	newTimeout := 5 * time.Second
	client.SetTimeout(newTimeout)

	if client.timeout != newTimeout {
		t.Errorf("expected timeout %v, got %v", newTimeout, client.timeout)
	}
}
