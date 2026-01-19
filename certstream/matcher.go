package certstream

import "strings"

// IsDomainMatch checks if a certificate domain matches a monitored domain
// Only matches exact domain or subdomains (e.g., nhn.no matches nhn.no or www.nhn.no, but NOT mynhn.no)
func IsDomainMatch(certDomain, watchDomain string) bool {
	// Check for empty domains first
	if certDomain == "" || watchDomain == "" {
		return false
	}

	certDomain = strings.ToLower(certDomain)
	watchDomain = strings.ToLower(watchDomain)

	// Exact match
	if certDomain == watchDomain {
		return true
	}

	// Subdomain match: cert domain must end with ".watchDomain"
	// This ensures mynhn.no doesn't match nhn.no, but www.nhn.no does
	if strings.HasSuffix(certDomain, "."+watchDomain) {
		return true
	}

	return false
}
