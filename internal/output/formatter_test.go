package output

import (
	"testing"
	"time"

	"github.com/jonasbg/certstream-monitor/certstream"
)

func TestNewFormatter(t *testing.T) {
	tests := []struct {
		name     string
		urlsOnly bool
		verbose  bool
	}{
		{"urls only mode", true, false},
		{"verbose mode", false, true},
		{"normal mode", false, false},
		{"both modes", true, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := NewFormatter(tt.urlsOnly, tt.verbose)
			if f == nil {
				t.Fatal("expected non-nil formatter")
			}
			if f.urlsOnly != tt.urlsOnly {
				t.Errorf("expected urlsOnly=%v, got %v", tt.urlsOnly, f.urlsOnly)
			}
			if f.verbose != tt.verbose {
				t.Errorf("expected verbose=%v, got %v", tt.verbose, f.verbose)
			}
		})
	}
}

func TestFormatter_FormatEvent(t *testing.T) {
	// Create a test event
	event := certstream.CertEvent{
		Certificate: certstream.CertData{
			MessageType: "certificate_update",
		},
		Timestamp: time.Now(),
		CertType:  "NEW",
	}

	// Set up certificate data
	event.Certificate.Data.LeafCert.AllDomains = []string{"example.com", "www.example.com"}
	event.Certificate.Data.LeafCert.Subject.CN = "example.com"
	event.Certificate.Data.LeafCert.Issuer.O = "Let's Encrypt"
	event.Certificate.Data.LeafCert.NotBefore = float64(time.Now().Unix())
	event.Certificate.Data.LeafCert.NotAfter = float64(time.Now().Add(90 * 24 * time.Hour).Unix())

	// Test with different formatter configurations
	tests := []struct {
		name     string
		urlsOnly bool
		verbose  bool
	}{
		{"normal mode", false, false},
		{"urls only", true, false},
		{"verbose mode", false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := NewFormatter(tt.urlsOnly, tt.verbose)
			// This should not panic
			f.FormatEvent(event)
		})
	}
}
