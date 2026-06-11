package engine

import (
	"bufio"
	"net"
	"os"
	"path/filepath"
	"sync"
)

// GeoIP manages the list of Vietnam IP subnets for country blocking during attacks.
type GeoIP struct {
	mu     sync.RWMutex
	vnNets []*net.IPNet
	logger interface {
		Println(v ...interface{})
		Printf(format string, v ...interface{})
	}
}

// NewGeoIP creates a new GeoIP validator and loads Vietnam IP ranges synchronously during startup.
func NewGeoIP(logger interface {
	Println(v ...interface{})
	Printf(format string, v ...interface{})
}) *GeoIP {
	g := &GeoIP{logger: logger}
	// Load IP ranges synchronously so they are available immediately when WAF starts
	g.LoadRanges()
	return g
}

// LoadRanges reads Vietnam IP ranges from a local vn.zone file.
func (g *GeoIP) LoadRanges() {
	g.logger.Println("[GeoIP] Loading Vietnam IP ranges from local vn.zone file...")
	filePath := filepath.Join("resources", "geo", "vn.zone")
	file, err := os.Open(filePath)
	if err != nil {
		g.logger.Printf("[GeoIP] Failed to open vn.zone: %v. Using fallback ISP ranges.", err)
		g.loadFallback()
		return
	}
	defer file.Close()

	var nets []*net.IPNet
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		_, ipNet, err := net.ParseCIDR(line)
		if err == nil {
			nets = append(nets, ipNet)
		}
	}

	if len(nets) == 0 {
		g.logger.Println("[GeoIP] Local vn.zone file is empty or invalid. Using fallback.")
		g.loadFallback()
		return
	}

	g.mu.Lock()
	g.vnNets = nets
	g.mu.Unlock()
	g.logger.Printf("[GeoIP] Successfully loaded %d Vietnam IP subnets from local file.", len(nets))
}

func (g *GeoIP) loadFallback() {
	// Fallback dải IP chính của các ISP Việt Nam (Viettel, VNPT, FPT...)
	fallbacks := []string{
		"1.52.0.0/14", "14.160.0.0/11", "27.64.0.0/12", "42.112.0.0/12", "58.186.0.0/15",
		"113.160.0.0/11", "115.72.0.0/13", "118.68.0.0/14", "123.16.0.0/12", "171.224.0.0/11",
		"220.231.0.0/16", "222.252.0.0/14",
	}
	var nets []*net.IPNet
	for _, cidr := range fallbacks {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil {
			nets = append(nets, ipNet)
		}
	}
	g.mu.Lock()
	g.vnNets = nets
	g.mu.Unlock()
}

// IsVietnamIP checks if the IP belongs to Vietnam, loopback, or private/local networks.
func (g *GeoIP) IsVietnamIP(ip net.IP) bool {
	if ip.IsLoopback() {
		return true
	}
	if ip.IsPrivate() || isLinkLocal(ip) {
		return true
	}

	g.mu.RLock()
	defer g.mu.RUnlock()

	// If map loading failed and no fallback, allow by default (fail-open)
	if len(g.vnNets) == 0 {
		return true
	}

	for _, ipNet := range g.vnNets {
		if ipNet.Contains(ip) {
			return true
		}
	}
	return false
}

func isLinkLocal(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		return ip4[0] == 169 && ip4[1] == 254
	}
	return false
}
