package engine

import (
	"net"
	"sync"
	"time"
)

type IPAction int

const (
	ActionNeutral IPAction = iota
	ActionWhitelist
	ActionBlacklist
)

// IPFilter implements Layer 0: High-speed static & dynamic Whitelist and Blacklist.
// Supports both single IPv4 addresses and CIDR subnets.
type IPFilter struct {
	mu sync.RWMutex

	// Fast exact-match maps
	whitelistIPs map[[4]byte]bool
	blacklistIPs map[[4]byte]int64 // Value: unix nano expiration (0 = permanent)

	// CIDR subnets
	whitelistCIDRs []*net.IPNet
	blacklistCIDRs []*net.IPNet
}

// NewIPFilter creates and initializes the Layer 0 IP filter.
func NewIPFilter(whitelist, blacklist []string) *IPFilter {
	f := &IPFilter{
		whitelistIPs: make(map[[4]byte]bool),
		blacklistIPs: make(map[[4]byte]int64),
	}

	for _, s := range whitelist {
		f.AddWhitelist(s)
	}

	for _, s := range blacklist {
		f.AddBlacklist(s, 0)
	}

	return f
}

// Check evaluates an IPv4 address against whitelist and blacklist.
func (f *IPFilter) Check(ip [4]byte) IPAction {
	f.mu.RLock()
	defer f.mu.RUnlock()

	// 1. Check exact Whitelist (Fast path)
	if f.whitelistIPs[ip] {
		return ActionWhitelist
	}

	// 2. Check exact Blacklist (Fast path)
	if exp, ok := f.blacklistIPs[ip]; ok {
		if exp == 0 || time.Now().UnixNano() < exp {
			return ActionBlacklist
		}
	}

	// Convert to net.IP for CIDR checking
	netIP := net.IPv4(ip[0], ip[1], ip[2], ip[3])

	// 3. Check Whitelist CIDRs
	for _, cidr := range f.whitelistCIDRs {
		if cidr.Contains(netIP) {
			return ActionWhitelist
		}
	}

	// 4. Check Blacklist CIDRs
	for _, cidr := range f.blacklistCIDRs {
		if cidr.Contains(netIP) {
			return ActionBlacklist
		}
	}

	return ActionNeutral
}

// AddWhitelist adds an IP or CIDR to the whitelist.
func (f *IPFilter) AddWhitelist(s string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()

	if ip := net.ParseIP(s); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			var b [4]byte
			copy(b[:], ip4)
			f.whitelistIPs[b] = true
			return true
		}
	}

	_, cidr, err := net.ParseCIDR(s)
	if err == nil {
		f.whitelistCIDRs = append(f.whitelistCIDRs, cidr)
		return true
	}

	return false
}

// AddBlacklist adds an IP or CIDR to the blacklist with optional duration (0 = permanent).
func (f *IPFilter) AddBlacklist(s string, duration time.Duration) bool {
	f.mu.Lock()
	defer f.mu.Unlock()

	var exp int64
	if duration > 0 {
		exp = time.Now().Add(duration).UnixNano()
	}

	if ip := net.ParseIP(s); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			var b [4]byte
			copy(b[:], ip4)
			f.blacklistIPs[b] = exp
			return true
		}
	}

	_, cidr, err := net.ParseCIDR(s)
	if err == nil {
		f.blacklistCIDRs = append(f.blacklistCIDRs, cidr)
		return true
	}

	return false
}

// RemoveBlacklist removes an IP from the blacklist.
func (f *IPFilter) RemoveBlacklist(ip [4]byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.blacklistIPs, ip)
}

// RemoveWhitelist removes an IP from the whitelist.
func (f *IPFilter) RemoveWhitelist(s string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()

	if ip := net.ParseIP(s); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			var b [4]byte
			copy(b[:], ip4)
			delete(f.whitelistIPs, b)
			return true
		}
	}
	return false
}

// GetWhitelist returns a slice of all whitelisted IPs and CIDRs.
func (f *IPFilter) GetWhitelist() []string {
	f.mu.RLock()
	defer f.mu.RUnlock()

	res := make([]string, 0, len(f.whitelistIPs)+len(f.whitelistCIDRs))
	for ip := range f.whitelistIPs {
		res = append(res, net.IPv4(ip[0], ip[1], ip[2], ip[3]).String())
	}
	for _, cidr := range f.whitelistCIDRs {
		res = append(res, cidr.String())
	}
	return res
}

// Count returns counts of whitelist and blacklist rules.
func (f *IPFilter) Count() (whitelistCount, blacklistCount int) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return len(f.whitelistIPs) + len(f.whitelistCIDRs), len(f.blacklistIPs) + len(f.blacklistCIDRs)
}

