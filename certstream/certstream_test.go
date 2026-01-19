package certstream

import "testing"

func TestIsDomainMatch(t *testing.T) {
	tests := []struct {
		certDomain  string
		watchDomain string
		want        bool
	}{
		{"www.nhn.no", "nhn.no", true},
		{"my.nhn.no", "nhn.no", true},
		{"nhn.no", "nhn.no", true},
		{"mynhn.no", "nhn.no", false},
		{"example.com", "example.org", false},
		{"sub.example.com", "example.com", true},
		{"", "example.com", false},
		{"example.com", "", false},
	}
	for _, tt := range tests {
		if got := IsDomainMatch(tt.certDomain, tt.watchDomain); got != tt.want {
			t.Errorf("IsDomainMatch(%q,%q) = %v; want %v", tt.certDomain, tt.watchDomain, got, tt.want)
		}
	}
}
