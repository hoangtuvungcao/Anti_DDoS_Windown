package engine

import (
	"net"
	"testing"
)

func TestGeoIP_BinarySearchLookups(t *testing.T) {
	geo := NewGeoIP(nil)

	// Test Vietnam IPs (from fallback ranges)
	vnIPs := []string{
		"1.52.1.1",        // 1.52.0.0/14
		"14.160.5.10",     // 14.160.0.0/11
		"27.65.100.200",   // 27.64.0.0/12
		"42.112.1.1",      // 42.112.0.0/12
		"113.161.2.3",     // 113.160.0.0/11
		"127.0.0.1",       // Loopback
		"192.168.1.100",   // Private RFC1918
		"10.0.0.1",        // Private RFC1918
		"100.64.0.1",      // CGNAT RFC6598 (Vietnam ISPs)
		"100.127.255.254", // CGNAT RFC6598
		"255.255.255.255", // Broadcast
	}

	for _, ipStr := range vnIPs {
		ip := net.ParseIP(ipStr)
		if !geo.IsAllowed(ip) {
			t.Errorf("Expected %s to be allowed in Vietnam/Private list, but was blocked", ipStr)
		}
	}

	// Test Foreign IPs (should not be in Vietnam list)
	foreignIPs := []string{
		"8.8.8.8",       // Google US
		"1.1.1.1",       // Cloudflare AU/US
		"185.220.101.5", // Tor exit node DE
		"45.33.32.156",  // Linode US
	}

	for _, ipStr := range foreignIPs {
		ip := net.ParseIP(ipStr)
		if geo.IsAllowed(ip) {
			t.Errorf("Expected foreign IP %s to be blocked, but was allowed", ipStr)
		}
	}
}
