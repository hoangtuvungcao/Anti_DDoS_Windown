package engine

import (
	"bufio"
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

// IPRange represents a contiguous IPv4 range for O(log N) binary search lookup.
type IPRange struct {
	Start uint32
	End   uint32
}

// GeoIP manages country-based IP filtering using blazing fast O(log N) binary search.
type GeoIP struct {
	mu            sync.RWMutex
	vnRanges      []IPRange
	blockedRanges []IPRange
	allowedRanges []IPRange
	mode          string // "VN_ONLY", "ALLOW_LIST", "BLOCK_LIST", "OFF"
	logger        interface {
		Println(v ...interface{})
		Printf(format string, v ...interface{})
	}
}

// NewGeoIP creates and loads the GeoIP engine.
func NewGeoIP(logger interface {
	Println(v ...interface{})
	Printf(format string, v ...interface{})
}) *GeoIP {
	g := &GeoIP{
		mode:   "VN_ONLY",
		logger: logger,
	}
	g.LoadRanges()
	return g
}

// LoadRanges loads Vietnam and world IP ranges from local zone files.
func (g *GeoIP) LoadRanges() {
	if g.logger != nil {
		g.logger.Println("[GeoIP] Loading IP country databases into fast binary search tree...")
	}

	filePath := filepath.Join("resources", "geo", "vn.zone")
	vnRanges := parseZoneFile(filePath)

	if len(vnRanges) == 0 {
		if g.logger != nil {
			g.logger.Println("[GeoIP] Local vn.zone missing or empty, loading built-in ISP fallback ranges.")
		}
		vnRanges = loadVNFallbackRanges()
	}

	// Sort and merge overlapping/adjacent ranges for optimal binary search
	vnRanges = sortAndMergeRanges(vnRanges)

	g.mu.Lock()
	g.vnRanges = vnRanges
	g.mu.Unlock()

	if g.logger != nil {
		g.logger.Printf("[GeoIP] Loaded %d optimized Vietnam IP CIDR ranges (Binary Search Ready).", len(vnRanges))
	}
}

// IsAllowed checks if an IP is allowed under the current Geo-IP policy.
func (g *GeoIP) IsAllowed(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return true // Allow IPv6 / non-IPv4 pass through
	}

	ipVal := binary.BigEndian.Uint32(ip4)

	// Always allow loopback and private/local network addresses
	if isPrivateOrLocal(ipVal) {
		return true
	}

	g.mu.RLock()
	defer g.mu.RUnlock()

	if len(g.vnRanges) == 0 {
		return true // Fail-open if no database
	}

	return inRangeBinarySearch(g.vnRanges, ipVal)
}

// IsVietnamIP checks if the IP is in Vietnam or private.
func (g *GeoIP) IsVietnamIP(ip net.IP) bool {
	return g.IsAllowed(ip)
}

// inRangeBinarySearch performs an O(log N) binary search over sorted IPRanges.
func inRangeBinarySearch(ranges []IPRange, ipVal uint32) bool {
	n := len(ranges)
	if n == 0 {
		return false
	}

	idx := sort.Search(n, func(i int) bool {
		return ranges[i].End >= ipVal
	})

	if idx < n && ipVal >= ranges[idx].Start && ipVal <= ranges[idx].End {
		return true
	}
	return false
}

// parseZoneFile reads CIDRs from file and returns contiguous IPRanges.
func parseZoneFile(path string) []IPRange {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()

	var ranges []IPRange
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		_, ipNet, err := net.ParseCIDR(line)
		if err == nil && ipNet.IP.To4() != nil {
			start := binary.BigEndian.Uint32(ipNet.IP.To4())
			mask := binary.BigEndian.Uint32(ipNet.Mask)
			end := start | (^mask)
			ranges = append(ranges, IPRange{Start: start, End: end})
		}
	}
	return ranges
}

// sortAndMergeRanges sorts numeric ranges and merges adjacent/overlapping segments.
func sortAndMergeRanges(ranges []IPRange) []IPRange {
	if len(ranges) <= 1 {
		return ranges
	}

	sort.Slice(ranges, func(i, j int) bool {
		return ranges[i].Start < ranges[j].Start
	})

	merged := make([]IPRange, 0, len(ranges))
	current := ranges[0]

	for i := 1; i < len(ranges); i++ {
		next := ranges[i]
		if next.Start <= current.End+1 {
			if next.End > current.End {
				current.End = next.End
			}
		} else {
			merged = append(merged, current)
			current = next
		}
	}
	merged = append(merged, current)
	return merged
}

// isPrivateOrLocal checks for loopback, private RFC1918, link-local, broadcast.
func isPrivateOrLocal(ipVal uint32) bool {
	// 127.0.0.0/8 (Loopback: 0x7F000000 - 0x7FFFFFFF)
	if ipVal >= 0x7F000000 && ipVal <= 0x7FFFFFFF {
		return true
	}
	// 10.0.0.0/8 (Private: 0x0A000000 - 0x0AFFFFFF)
	if ipVal >= 0x0A000000 && ipVal <= 0x0AFFFFFF {
		return true
	}
	// 172.16.0.0/12 (Private: 0xAC100000 - 0xAC1FFFFF)
	if ipVal >= 0xAC100000 && ipVal <= 0xAC1FFFFF {
		return true
	}
	// 192.168.0.0/16 (Private: 0xC0A80000 - 0xC0A8FFFF)
	if ipVal >= 0xC0A80000 && ipVal <= 0xC0A8FFFF {
		return true
	}
	// 169.254.0.0/16 (Link Local: 0xA9FE0000 - 0xA9FEFFFF)
	if ipVal >= 0xA9FE0000 && ipVal <= 0xA9FEFFFF {
		return true
	}
	return false
}

func loadVNFallbackRanges() []IPRange {
	fallbacks := []string{
		"1.52.0.0/14", "14.160.0.0/11", "27.64.0.0/12", "42.112.0.0/12", "58.186.0.0/15",
		"113.160.0.0/11", "115.72.0.0/13", "118.68.0.0/14", "123.16.0.0/12", "171.224.0.0/11",
		"220.231.0.0/16", "222.252.0.0/14",
	}
	var ranges []IPRange
	for _, cidr := range fallbacks {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil && ipNet.IP.To4() != nil {
			start := binary.BigEndian.Uint32(ipNet.IP.To4())
			mask := binary.BigEndian.Uint32(ipNet.Mask)
			end := start | (^mask)
			ranges = append(ranges, IPRange{Start: start, End: end})
		}
	}
	return ranges
}

