package engine

import (
	"testing"
	"time"
)

func TestIPFilter_WhitelistAndBlacklist(t *testing.T) {
	whitelist := []string{"127.0.0.1", "10.0.0.0/8"}
	blacklist := []string{"203.0.113.5", "198.51.100.0/24"}

	f := NewIPFilter(whitelist, blacklist)

	// 1. Exact Whitelist
	if action := f.Check([4]byte{127, 0, 0, 1}); action != ActionWhitelist {
		t.Errorf("Expected ActionWhitelist for 127.0.0.1, got %v", action)
	}

	// 2. CIDR Whitelist
	if action := f.Check([4]byte{10, 50, 1, 99}); action != ActionWhitelist {
		t.Errorf("Expected ActionWhitelist for 10.50.1.99, got %v", action)
	}

	// 3. Exact Blacklist
	if action := f.Check([4]byte{203, 0, 113, 5}); action != ActionBlacklist {
		t.Errorf("Expected ActionBlacklist for 203.0.113.5, got %v", action)
	}

	// 4. CIDR Blacklist
	if action := f.Check([4]byte{198, 51, 100, 42}); action != ActionBlacklist {
		t.Errorf("Expected ActionBlacklist for 198.51.100.42, got %v", action)
	}

	// 5. Neutral (Unlisted) IP
	if action := f.Check([4]byte{1, 1, 1, 1}); action != ActionNeutral {
		t.Errorf("Expected ActionNeutral for 1.1.1.1, got %v", action)
	}

	// 6. Dynamic Temporary Blacklist
	f.AddBlacklist("192.0.2.100", 500*time.Millisecond)
	if action := f.Check([4]byte{192, 0, 2, 100}); action != ActionBlacklist {
		t.Errorf("Expected ActionBlacklist for temporary IP, got %v", action)
	}

	time.Sleep(600 * time.Millisecond)
	if action := f.Check([4]byte{192, 0, 2, 100}); action != ActionNeutral {
		t.Errorf("Expected ActionNeutral after expiration, got %v", action)
	}
}
