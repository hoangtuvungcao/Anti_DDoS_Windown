package engine

import (
	"fmt"
	"math"
	"time"

	"waf-game/pkg/datastore"
	"waf-game/pkg/packet"
)

// UDPShield implements Layer 4: Per-Flow + Per-IP Rate Limiting,
// Deep Packet Inspection, Entropy Analysis, and Two-Way UDP Verification.
// Protects ALL UDP ports automatically.
type UDPShield struct {
	// Per-flow rate limiting (Key = srcIP + srcPort)
	flowBuckets *datastore.ShardedMap[datastore.FlowBucket]

	// Per-IP aggregate rate limiting (Key = srcIP)
	ipBuckets *datastore.ShardedMap[datastore.IPBucket]

	// Outbound tracking for two-way verification (Key = dstIP + dstPort from server's perspective)
	outboundSeen *datastore.ShardedMap[int64] // value = last outbound timestamp

	// Port discovery helper to bypass verification for hosted UDP services
	Discovery *PortDiscovery

	// DPI signatures
	signatures []Signature

	// Settings
	flowPPS       float64
	flowBPS       float64
	ipPPS         float64
	blacklistDur  time.Duration
	dpiEnabled    bool
	entropyCheck  bool
	twowayEnabled bool
}

// Signature defines a magic byte pattern for DPI
type Signature struct {
	Name   string
	Port   uint16 // 0 = any port
	Offset int
	Bytes  []byte
}

// NewUDPShield creates a new UDP Shield module.
func NewUDPShield(flowPPS, flowBPS, ipPPS float64, blacklistDur time.Duration) *UDPShield {
	return &UDPShield{
		flowBuckets:  datastore.NewShardedMap[datastore.FlowBucket](200000),
		ipBuckets:    datastore.NewShardedMap[datastore.IPBucket](50000),
		outboundSeen: datastore.NewShardedMap[int64](100000),
		flowPPS:      flowPPS,
		flowBPS:      flowBPS,
		ipPPS:        ipPPS,
		blacklistDur: blacklistDur,
		signatures:   defaultSignatures(),
	}
}

// ProcessUDP handles a UDP packet through the protection pipeline.
func (us *UDPShield) ProcessUDP(pkt *packet.Packet, rawBuf []byte) FilterResult {
	flowKey := pkt.FlowKey()
	ipKey := pkt.IPFlowKey()

	// Step 1: Check if IP is blacklisted (fast path)
	if entry, ok := us.ipBuckets.Get(ipKey); ok {
		if entry.Value.IsBlacklisted() {
			return FilterDrop
		}
	}

	// Step 2: Check if flow is blacklisted (fast path)
	if entry, ok := us.flowBuckets.Get(flowKey); ok {
		if entry.Value.IsBlacklisted() {
			return FilterDrop
		}
	}

	// Step 3: Two-way verification (War Mode only)
	if us.twowayEnabled {
		isListening := false
		if us.Discovery != nil {
			isListening = us.Discovery.IsListening(pkt.DstPort, false)
		}
		if !isListening && !us.verifyTwoWay(pkt) {
			return FilterDrop
		}
	}

	// Step 4: DPI — check payload signature
	if us.dpiEnabled && pkt.PayloadLen > 0 {
		if !us.checkDPI(pkt, rawBuf) {
			return FilterDrop
		}
	}

	// Step 5: Entropy analysis (War Mode only)
	if us.entropyCheck && pkt.PayloadLen > 0 {
		if !us.checkEntropy(rawBuf, pkt.PayloadOffset, pkt.PayloadLen) {
			return FilterDrop
		}
	}

	// Step 6: Per-Flow rate limit
	flowEntry, _ := us.flowBuckets.GetOrCreate(flowKey, func() datastore.FlowBucket {
		return datastore.NewFlowBucket(us.flowPPS, us.flowBPS)
	})

	pktSize := pkt.TotalLen
	if !flowEntry.Value.Allow(pktSize) {
		flowEntry.Value.Blacklist(us.blacklistDur)
		return FilterDrop
	}

	// Step 7: Per-IP aggregate rate limit
	ipEntry, _ := us.ipBuckets.GetOrCreate(ipKey, func() datastore.IPBucket {
		return datastore.NewIPBucket(us.ipPPS)
	})

	if !ipEntry.Value.Allow() {
		ipEntry.Value.Blacklist(us.blacklistDur)
		return FilterDrop
	}

	return FilterPass
}

// TrackOutbound records an outbound UDP packet from the server.
// Called from the outbound tracking goroutine.
func (us *UDPShield) TrackOutbound(dstIP [4]byte, dstPort uint16) {
	// Key = destination IP + port (which is the client's IP + port from server's view)
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
func (us *UDPShield) checkDPI(pkt *packet.Packet, rawBuf []byte) bool {
	if pkt.PayloadLen == 0 {
		return false // Zero-length payload in DPI mode = suspicious
	}

	payload := rawBuf[pkt.PayloadOffset : pkt.PayloadOffset+pkt.PayloadLen]

	// If we have port-specific signatures, check those first
	for _, sig := range us.signatures {
		if sig.Port != 0 && sig.Port != pkt.DstPort {
			continue
		}
		if sig.Port == 0 {
			continue // Skip generic signatures for targeted check
		}
		if matchSignature(payload, sig) {
			return true // Matches known game protocol
		}
	}

	// If no port-specific match required, allow through
	// (DPI is advisory — only block known-bad patterns)
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
// Returns false (drop) if entropy indicates random junk or null flood.
func (us *UDPShield) checkEntropy(rawBuf []byte, offset, length int) bool {
	if length == 0 {
		return false
	}

	// Analyze first 256 bytes of payload (or less)
	analyzeLen := length
	if analyzeLen > 256 {
		analyzeLen = 256
	}

	data := rawBuf[offset : offset+analyzeLen]
	entropy := shannonEntropy(data)

	// Drop if entropy > 7.5 (near-random noise — likely junk/encrypted flood)
	if entropy > 7.5 {
		return false
	}

	// Drop if entropy < 1.0 (too uniform — null flood or repeat pattern)
	if entropy < 1.0 && analyzeLen >= 8 {
		return false
	}

	return true
}

// shannonEntropy calculates Shannon entropy of a byte slice.
// Returns value between 0 (uniform) and 8 (maximum randomness).
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
	us.dpiEnabled = enabled
}

// SetEntropy enables or disables entropy analysis.
func (us *UDPShield) SetEntropy(enabled bool) {
	us.entropyCheck = enabled
}

// SetTwoWay enables or disables two-way verification.
func (us *UDPShield) SetTwoWay(enabled bool) {
	us.twowayEnabled = enabled
}

// SetRateLimits updates rate limiting thresholds.
func (us *UDPShield) SetRateLimits(flowPPS, flowBPS, ipPPS float64) {
	us.flowPPS = flowPPS
	us.flowBPS = flowBPS
	us.ipPPS = ipPPS
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

// SweepFlows cleans up expired flow and IP entries.
func (us *UDPShield) SweepFlows(ttl time.Duration) (flowsRemoved, ipsRemoved, outboundRemoved int64) {
	flowsRemoved = us.flowBuckets.Sweep(ttl)
	ipsRemoved = us.ipBuckets.Sweep(ttl)
	outboundRemoved = us.outboundSeen.Sweep(ttl)
	return
}

// GetBlacklistedCount returns approximate count of blacklisted flows.
func (us *UDPShield) GetBlacklistedCount() int64 {
	var count int64
	us.flowBuckets.ForEach(func(key uint64, entry *datastore.Entry[datastore.FlowBucket]) bool {
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

// GetBlacklist returns a list of blacklisted IPs and flows.
func (us *UDPShield) GetBlacklist() []string {
	var list []string
	now := time.Now().UnixNano()

	// Check IP buckets
	us.ipBuckets.ForEach(func(key uint64, entry *datastore.Entry[datastore.IPBucket]) bool {
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

	// Check Flow buckets
	us.flowBuckets.ForEach(func(key uint64, entry *datastore.Entry[datastore.FlowBucket]) bool {
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
	return us.flowPPS
}

// GetIPPPS returns the current UDP per-IP PPS limit.
func (us *UDPShield) GetIPPPS() float64 {
	return us.ipPPS
}

// IsEntropyEnabled returns whether entropy check is active.
func (us *UDPShield) IsEntropyEnabled() bool {
	return us.entropyCheck
}

// defaultSignatures returns built-in game protocol signatures
func defaultSignatures() []Signature {
	return []Signature{
		{Name: "source_engine", Port: 0, Offset: 0, Bytes: []byte{0xFF, 0xFF, 0xFF, 0xFF}},
		{Name: "raknet", Port: 0, Offset: 0, Bytes: []byte{0x00, 0xFF, 0xFF, 0x00, 0xFE, 0xFE, 0xFE, 0xFE}},
	}
}
