package engine

import (
	"fmt"
	"math"
	"sync"
	"time"

	"waf-game/pkg/datastore"
	"waf-game/pkg/packet"
)

// UDPShield implements Layer 4: 3-Tier Rate Limiting (Flow + IP + Subnet /24),
// Deep Packet Inspection, Entropy Analysis, Two-Way Verification, and Game Shield.
type UDPShield struct {
	mu sync.RWMutex
	// 1. Per-flow rate limiting (Key = srcIP + srcPort)
	flowBuckets *datastore.ShardedMap[*datastore.FlowBucket]

	// 2. Per-IP aggregate rate limiting (Key = srcIP)
	ipBuckets *datastore.ShardedMap[*datastore.IPBucket]

	// 3. Per-Subnet (/24) aggregate rate limiting (Key = srcIP >> 8)
	subnetBuckets *datastore.ShardedMap[*datastore.SubnetBucket]

	// Outbound tracking for two-way verification
	outboundSeen *datastore.ShardedMap[int64]

	// Port discovery helper
	Discovery *PortDiscovery

	// Game protocol shield (Layer 4.5)
	GameShield *GameShield

	// Optional operator-supplied deny signatures; game headers are never denied by default.
	signatures []Signature

	// Settings
	flowPPS       float64
	flowBPS       float64
	ipPPS         float64
	subnetPPS     float64
	blacklistDur  time.Duration
	dpiEnabled    bool
	entropyCheck  bool
	twowayEnabled bool
	strict        bool
}

// Signature defines a magic byte pattern for DPI
type Signature struct {
	Name   string
	Port   uint16 // 0 = any port
	Offset int
	Bytes  []byte
}

// NewUDPShield creates a new UDP Shield module.
func NewUDPShield(flowPPS, flowBPS, ipPPS, subnetPPS float64, blacklistDur time.Duration, gameRules []CustomGameRule) *UDPShield {
	if subnetPPS <= 0 {
		subnetPPS = 500
	}

	return &UDPShield{
		flowBuckets:   datastore.NewShardedMap[*datastore.FlowBucket](200000),
		ipBuckets:     datastore.NewShardedMap[*datastore.IPBucket](50000),
		subnetBuckets: datastore.NewShardedMap[*datastore.SubnetBucket](20000),
		outboundSeen:  datastore.NewShardedMap[int64](100000),
		GameShield:    NewGameShield(gameRules),
		flowPPS:       flowPPS,
		flowBPS:       flowBPS,
		ipPPS:         ipPPS,
		subnetPPS:     subnetPPS,
		blacklistDur:  blacklistDur,
		signatures:    nil,
	}
}

// ProcessUDP handles a UDP packet through the 3-tier protection pipeline.
func (us *UDPShield) ProcessUDP(pkt *packet.Packet, rawBuf []byte) FilterResult {
	result, _ := us.ProcessUDPWithReason(pkt, rawBuf)
	return result
}

// ProcessUDPWithReason runs the UDP pipeline and returns an observable drop reason.
func (us *UDPShield) ProcessUDPWithReason(pkt *packet.Packet, rawBuf []byte) (FilterResult, DropReason) {
	us.mu.RLock()
	flowPPS, flowBPS := us.flowPPS, us.flowBPS
	ipPPS, subnetPPS := us.ipPPS, us.subnetPPS
	blacklistDur := us.blacklistDur
	dpiEnabled, entropyCheck := us.dpiEnabled, us.entropyCheck
	twowayEnabled := us.twowayEnabled
	strict := us.strict
	us.mu.RUnlock()
	flowKey := pkt.FlowKey()
	ipKey := pkt.IPFlowKey()
	subnetKey := uint64(pkt.SrcIPUint32() >> 8)

	// Step 1: Fast check: is this IP blacklisted?
	if entry, ok := us.ipBuckets.Get(ipKey); ok {
		if entry.Value.IsBlacklisted() {
			return FilterDrop, DropBlacklisted
		}
	}

	// Step 2: Fast check: is this Subnet (/24) blacklisted?
	if entry, ok := us.subnetBuckets.Get(subnetKey); ok {
		if entry.Value.IsBlacklisted() {
			return FilterDrop, DropSubnetRate
		}
	}

	// Step 3: Fast check: is this Flow blacklisted?
	if entry, ok := us.flowBuckets.Get(flowKey); ok {
		if entry.Value.IsBlacklisted() {
			return FilterDrop, DropBlacklisted
		}
	}

	// Step 4: Check Two-Way verification (if enforced in War Mode)
	isVerifiedClient := us.verifyTwoWay(pkt)
	if twowayEnabled && !isVerifiedClient {
		// In strict two-way mode, unverified inbound UDP is rate-limited without banning
		unverifiedIPEntry, _ := us.ipBuckets.GetOrCreate(ipKey, func() *datastore.IPBucket {
			return datastore.NewIPBucket(60) // Generous 60 PPS for handshake
		})
		if !unverifiedIPEntry.Value.Allow() {
			return FilterDrop, DropUnverified
		}
	}

	// Step 5: Game Protocol & Query Flood Shield (Layer 4.5)
	if us.GameShield != nil && pkt.PayloadLen > 0 {
		payload := rawBuf[pkt.PayloadOffset : pkt.PayloadOffset+pkt.PayloadLen]
		if res := us.GameShield.CheckGamePacket(pkt, payload); res == FilterDrop {
			return FilterDrop, DropGameQuery
		}
	}

	// Step 6: DPI — check payload signature
	if dpiEnabled && pkt.PayloadLen > 0 {
		if !us.checkDPI(pkt, rawBuf) {
			return FilterDrop, DropDPI
		}
	}

	// Step 7: Entropy analysis (War Mode only)
	if entropyCheck && pkt.PayloadLen > 0 {
		if !us.checkEntropy(rawBuf, pkt.PayloadOffset, pkt.PayloadLen) {
			return FilterDrop, DropEntropy
		}
	}

	// Step 8: Per-Flow rate limit (Tier 1)
	flowEntry, _ := us.flowBuckets.GetOrCreate(flowKey, func() *datastore.FlowBucket {
		return datastore.NewFlowBucket(flowPPS, flowBPS)
	})

	pktSize := pkt.TotalLen
	if !flowEntry.Value.Allow(pktSize) {
		// Only blacklist under active War Mode attack with 150+ continuous flood violations
		if strict && flowEntry.Value.ViolationCount() >= 150 {
			flowEntry.Value.Blacklist(blacklistDur)
		}
		return FilterDrop, DropFlowRate
	}

	// Step 9: Per-IP aggregate rate limit (Tier 2)
	ipEntry, _ := us.ipBuckets.GetOrCreate(ipKey, func() *datastore.IPBucket {
		return datastore.NewIPBucket(ipPPS)
	})

	if !ipEntry.Value.Allow() {
		if strict && ipEntry.Value.ViolationCount() >= 200 {
			ipEntry.Value.Blacklist(blacklistDur)
		}
		return FilterDrop, DropIPRate
	}

	// Step 10: Per-Subnet (/24) aggregate rate limit (Tier 3 - defeats distributed botnets)
	subnetEntry, _ := us.subnetBuckets.GetOrCreate(subnetKey, func() *datastore.SubnetBucket {
		return datastore.NewSubnetBucket(subnetPPS)
	})

	if !subnetEntry.Value.Allow() {
		if strict && subnetEntry.Value.ViolationCount() >= 500 {
			subnetEntry.Value.Blacklist(blacklistDur)
		}
		return FilterDrop, DropSubnetRate
	}

	return FilterPass, DropNone
}

// TrackOutbound records an outbound UDP packet from the server.
func (us *UDPShield) TrackOutbound(dstIP [4]byte, dstPort uint16) {
	key := uint64(dstIP[0])<<24 | uint64(dstIP[1])<<16 | uint64(dstIP[2])<<8 | uint64(dstIP[3])
	key = key<<16 | uint64(dstPort)
	us.outboundSeen.Set(key, time.Now().UnixNano())
}

// verifyTwoWay checks if the server has responded to this client before.
func (us *UDPShield) verifyTwoWay(pkt *packet.Packet) bool {
	key := uint64(pkt.SrcIPUint32())<<16 | uint64(pkt.SrcPort)
	_, exists := us.outboundSeen.Get(key)
	return exists
}

// checkDPI verifies packet payload against known signatures.
// Returns false (DROP) if a signature is matched on a blocked port.
// Port=0 in a signature means "match on any port".
func (us *UDPShield) checkDPI(pkt *packet.Packet, rawBuf []byte) bool {
	if pkt.PayloadLen == 0 {
		return true
	}

	payload := rawBuf[pkt.PayloadOffset : pkt.PayloadOffset+pkt.PayloadLen]

	for _, sig := range us.signatures {
		// sig.Port == 0 means match on any destination port
		if sig.Port != 0 && sig.Port != pkt.DstPort {
			continue
		}
		if matchSignature(payload, sig) {
			return false // DROP: matched a blocked signature
		}
	}

	return true
}

func matchSignature(payload []byte, sig Signature) bool {
	if sig.Offset+len(sig.Bytes) > len(payload) {
		return false
	}
	for i, b := range sig.Bytes {
		if payload[sig.Offset+i] != b {
			return false
		}
	}
	return true
}

// checkEntropy performs Shannon entropy analysis on payload.
func (us *UDPShield) checkEntropy(rawBuf []byte, offset, length int) bool {
	if length == 0 {
		return false
	}

	analyzeLen := length
	if analyzeLen > 256 {
		analyzeLen = 256
	}

	data := rawBuf[offset : offset+analyzeLen]
	entropy := shannonEntropy(data)

	// Drop if entropy is pure flat random noise (> 7.98) on large buffers
	if entropy > 7.98 && analyzeLen >= 128 {
		return false
	}

	// Drop if entropy < 0.5 (null flood or repetitive pattern)
	if entropy < 0.5 && analyzeLen >= 16 {
		return false
	}

	return true
}

func shannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}

	var freq [256]int
	for _, b := range data {
		freq[b]++
	}

	n := float64(len(data))
	entropy := 0.0

	for _, count := range freq {
		if count == 0 {
			continue
		}
		p := float64(count) / n
		entropy -= p * math.Log2(p)
	}

	return entropy
}

// SetDPI enables or disables Deep Packet Inspection.
func (us *UDPShield) SetDPI(enabled bool) {
	us.mu.Lock()
	defer us.mu.Unlock()
	us.dpiEnabled = enabled
}

// SetEntropy enables or disables entropy analysis.
func (us *UDPShield) SetEntropy(enabled bool) {
	us.mu.Lock()
	defer us.mu.Unlock()
	us.entropyCheck = enabled
}

// SetTwoWay enables or disables two-way verification.
func (us *UDPShield) SetTwoWay(enabled bool) {
	us.mu.Lock()
	defer us.mu.Unlock()
	us.twowayEnabled = enabled
}

// SetStrict enables or disables strict War Mode mitigation (including flood blacklisting).
func (us *UDPShield) SetStrict(enabled bool) {
	us.mu.Lock()
	defer us.mu.Unlock()
	us.strict = enabled
}

// SetRateLimits updates rate limiting thresholds.
func (us *UDPShield) SetRateLimits(flowPPS, flowBPS, ipPPS, subnetPPS float64) {
	us.mu.Lock()
	us.flowPPS = flowPPS
	us.flowBPS = flowBPS
	us.ipPPS = ipPPS
	if subnetPPS > 0 {
		us.subnetPPS = subnetPPS
	}
	us.mu.Unlock()
	us.flowBuckets.ForEach(func(_ uint64, entry *datastore.Entry[*datastore.FlowBucket]) bool {
		entry.Value.SetLimits(flowPPS, flowBPS)
		return true
	})
	us.ipBuckets.ForEach(func(_ uint64, entry *datastore.Entry[*datastore.IPBucket]) bool {
		entry.Value.SetLimit(ipPPS)
		return true
	})
	if subnetPPS > 0 {
		us.subnetBuckets.ForEach(func(_ uint64, entry *datastore.Entry[*datastore.SubnetBucket]) bool {
			entry.Value.SetLimit(subnetPPS)
			return true
		})
	}
}

// AddSignature adds a DPI signature.
func (us *UDPShield) AddSignature(name string, port uint16, offset int, magic []byte) {
	us.signatures = append(us.signatures, Signature{
		Name:   name,
		Port:   port,
		Offset: offset,
		Bytes:  magic,
	})
}

// SweepFlows cleans up expired flow, IP, subnet, and outbound entries.
func (us *UDPShield) SweepFlows(ttl time.Duration) (flowsRemoved, ipsRemoved, outboundRemoved int64) {
	flowsRemoved = us.flowBuckets.Sweep(ttl)
	ipsRemoved = us.ipBuckets.Sweep(ttl)
	_ = us.subnetBuckets.Sweep(ttl)
	outboundRemoved = us.outboundSeen.Sweep(ttl)
	if us.GameShield != nil {
		_ = us.GameShield.Sweep(ttl)
	}
	return
}

// EnforceCapacity applies the configured aggregate cache ceiling across UDP
// flow, IP, subnet and two-way state stores.
func (us *UDPShield) EnforceCapacity(maxEntries int) int64 {
	if maxEntries < 1000 {
		maxEntries = 1000
	}
	var removed int64
	removed += us.flowBuckets.EvictOldest(maxEntries * 45 / 100)
	removed += us.ipBuckets.EvictOldest(maxEntries * 15 / 100)
	removed += us.subnetBuckets.EvictOldest(maxEntries * 15 / 100)
	removed += us.outboundSeen.EvictOldest(maxEntries * 15 / 100)
	if us.GameShield != nil {
		removed += us.GameShield.EnforceCapacity(maxEntries / 10)
	}
	return removed
}

// GetBlacklistedCount returns approximate count of blacklisted flows.
func (us *UDPShield) GetBlacklistedCount() int64 {
	var count int64
	us.flowBuckets.ForEach(func(key uint64, entry *datastore.Entry[*datastore.FlowBucket]) bool {
		if entry.Value.IsBlacklisted() {
			count++
		}
		return true
	})
	return count
}

// GetFlowCount returns total tracked flows.
func (us *UDPShield) GetFlowCount() int64 {
	return us.flowBuckets.Count()
}

// GetBlacklist returns a list of blacklisted IPs, Subnets, and flows.
func (us *UDPShield) GetBlacklist() []string {
	var list []string
	now := time.Now().UnixNano()

	// Check IP buckets
	us.ipBuckets.ForEach(func(key uint64, entry *datastore.Entry[*datastore.IPBucket]) bool {
		if entry.Value.IsBlacklisted() {
			val := entry.Value
			ip := fmt.Sprintf("%d.%d.%d.%d", byte(key>>24), byte(key>>16), byte(key>>8), byte(key))
			rem := time.Duration(val.BlacklistUntil - now).Truncate(time.Second)
			if rem < 0 {
				rem = 0
			}
			list = append(list, fmt.Sprintf("%-22s │ UDP IP   │ %s", ip, rem))
		}
		return len(list) < 8
	})

	// Check Subnet buckets
	us.subnetBuckets.ForEach(func(key uint64, entry *datastore.Entry[*datastore.SubnetBucket]) bool {
		if entry.Value.IsBlacklisted() {
			val := entry.Value
			subnet := fmt.Sprintf("%d.%d.%d.0/24", byte(key>>16), byte(key>>8), byte(key))
			rem := time.Duration(val.BlacklistUntil - now).Truncate(time.Second)
			if rem < 0 {
				rem = 0
			}
			list = append(list, fmt.Sprintf("%-22s │ Subnet/24│ %s", subnet, rem))
		}
		return len(list) < 8
	})

	// Check Flow buckets
	us.flowBuckets.ForEach(func(key uint64, entry *datastore.Entry[*datastore.FlowBucket]) bool {
		if entry.Value.IsBlacklisted() {
			val := entry.Value
			ipVal := uint32(key >> 16)
			port := uint16(key)
			ip := fmt.Sprintf("%d.%d.%d.%d:%d", byte(ipVal>>24), byte(ipVal>>16), byte(ipVal>>8), byte(ipVal), port)
			rem := time.Duration(val.BlacklistUntil - now).Truncate(time.Second)
			if rem < 0 {
				rem = 0
			}
			list = append(list, fmt.Sprintf("%-22s │ UDP Flow │ %s", ip, rem))
		}
		return len(list) < 8
	})

	return list
}

// GetFlowPPS returns the current UDP per-flow PPS limit.
func (us *UDPShield) GetFlowPPS() float64 {
	us.mu.RLock()
	defer us.mu.RUnlock()
	return us.flowPPS
}

// GetIPPPS returns the current UDP per-IP PPS limit.
func (us *UDPShield) GetIPPPS() float64 {
	us.mu.RLock()
	defer us.mu.RUnlock()
	return us.ipPPS
}

// GetSubnetPPS returns the current UDP per-subnet PPS limit.
func (us *UDPShield) GetSubnetPPS() float64 {
	us.mu.RLock()
	defer us.mu.RUnlock()
	return us.subnetPPS
}

// IsEntropyEnabled returns whether entropy check is active.
func (us *UDPShield) IsEntropyEnabled() bool {
	us.mu.RLock()
	defer us.mu.RUnlock()
	return us.entropyCheck
}
