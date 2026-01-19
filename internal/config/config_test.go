package config

import (
	"os"
	"testing"
	"time"
)

func TestSanitizeDomains(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "comma separated",
			input:    "example.com,test.com",
			expected: []string{"example.com", "test.com"},
		},
		{
			name:     "space separated",
			input:    "example.com test.com",
			expected: []string{"example.com", "test.com"},
		},
		{
			name:     "mixed separators",
			input:    "example.com, test.com another.com",
			expected: []string{"example.com", "test.com", "another.com"},
		},
		{
			name:     "with extra spaces",
			input:    "  example.com  ,  test.com  ",
			expected: []string{"example.com", "test.com"},
		},
		{
			name:     "empty string",
			input:    "",
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeDomains(tt.input)
			if len(result) != len(tt.expected) {
				t.Fatalf("expected %d domains, got %d", len(tt.expected), len(result))
			}
			for i, domain := range result {
				if domain != tt.expected[i] {
					t.Errorf("expected domain[%d] = %q, got %q", i, tt.expected[i], domain)
				}
			}
		})
	}
}

func TestCLIConfig_ReconnectTimeout(t *testing.T) {
	cfg := &CLIConfig{ReconnectTimeoutSec: 5}
	expected := 5 * time.Second
	if got := cfg.ReconnectTimeout(); got != expected {
		t.Errorf("expected %v, got %v", expected, got)
	}
}

func TestCLIConfig_HasDomains(t *testing.T) {
	tests := []struct {
		name     string
		domains  []string
		expected bool
	}{
		{"with domains", []string{"example.com"}, true},
		{"empty slice", []string{}, false},
		{"nil slice", nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &CLIConfig{Domains: tt.domains}
			if got := cfg.HasDomains(); got != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, got)
			}
		})
	}
}

func TestParseDomains(t *testing.T) {
	// Save original env var
	originalEnv := os.Getenv("TARGET_DOMAINS")
	defer os.Setenv("TARGET_DOMAINS", originalEnv)

	tests := []struct {
		name     string
		envVar   string
		args     []string
		expected []string
	}{
		{
			name:     "args override env",
			envVar:   "env1.com,env2.com",
			args:     []string{"arg1.com", "arg2.com"},
			expected: []string{"arg1.com", "arg2.com"},
		},
		{
			name:     "use env when no args",
			envVar:   "env1.com,env2.com",
			args:     []string{},
			expected: []string{"env1.com", "env2.com"},
		},
		{
			name:     "no env no args",
			envVar:   "",
			args:     []string{},
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Setenv("TARGET_DOMAINS", tt.envVar)
			result := parseDomains(tt.args)

			if len(result) != len(tt.expected) {
				t.Fatalf("expected %d domains, got %d", len(tt.expected), len(result))
			}
			for i, domain := range result {
				if domain != tt.expected[i] {
					t.Errorf("expected domain[%d] = %q, got %q", i, tt.expected[i], domain)
				}
			}
		})
	}
}
