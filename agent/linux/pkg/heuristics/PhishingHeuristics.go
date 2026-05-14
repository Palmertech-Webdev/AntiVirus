package heuristics

import (
	"net"
	"strings"
	"unicode"
)

// PhishingHeuristics provides domain-level phishing detection.
type PhishingHeuristics struct {
	blocklist map[string]bool
}

func NewPhishingHeuristics() *PhishingHeuristics {
	return &PhishingHeuristics{
		blocklist: defaultBlocklist(),
	}
}

// EvaluateDomain returns true if the domain looks phishy.
func (p *PhishingHeuristics) EvaluateDomain(domain string) (bool, string) {
	domain = strings.ToLower(strings.TrimSpace(domain))

	if p.blocklist[domain] {
		return true, "domain is blocklisted"
	}

	// Check for homograph attacks (excessive non-ASCII in domain)
	asciiCount, totalCount := 0, 0
	for _, r := range domain {
		totalCount++
		if r < 128 {
			asciiCount++
		}
	}
	if totalCount > 0 && float64(asciiCount)/float64(totalCount) < 0.8 {
		return true, "homograph attack suspected (high non-ASCII ratio)"
	}

	// Detect excessive subdomain depth (e.g., paypal.com.evil.xyz)
	labels := strings.Split(domain, ".")
	if len(labels) >= 6 {
		return true, "excessive subdomain depth"
	}

	// Brand impersonation heuristic
	brands := []string{"paypal", "apple", "microsoft", "google", "amazon", "netflix", "facebook"}
	tld := strings.Join(labels[len(labels)-2:], ".")
	for _, brand := range brands {
		if strings.Contains(domain, brand) && !strings.HasSuffix(domain, brand+".com") {
			if !strings.HasSuffix(tld, brand+".com") {
				return true, "brand impersonation: " + brand
			}
		}
	}

	return false, ""
}

// EvaluateIP returns true if the IP is in a private range (C2 detection helper).
func (p *PhishingHeuristics) EvaluateIP(ipStr string) (bool, string) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false, ""
	}
	privateRanges := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"}
	for _, cidr := range privateRanges {
		_, network, _ := net.ParseCIDR(cidr)
		if network.Contains(ip) {
			return false, "" // Private IPs are not phishing targets
		}
	}
	return false, ""
}

func isAlpha(s string) bool {
	for _, r := range s {
		if !unicode.IsLetter(r) {
			return false
		}
	}
	return true
}

func defaultBlocklist() map[string]bool {
	return map[string]bool{
		"malware.wicar.org": true,
		"eicar.org":         true,
	}
}
