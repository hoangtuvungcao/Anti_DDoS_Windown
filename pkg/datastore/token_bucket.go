package datastore

import (
	"sync"
	"time"
)

// FlowBucket implements Token Bucket rate limiting for a single flow.
// Tracks both PPS (packets per second) and BPS (bytes per second).
type FlowBucket struct {
	mu sync.Mutex

	// PPS limiting
	PacketTokens float64 // Current available packet tokens
	MaxPPS       float64 // Max tokens (= refill rate per second)

	// BPS limiting
	ByteTokens float64 // Current available byte tokens
	MaxBPS     float64 // Max bytes per second

	// Timing
	LastRefill int64 // unix nano of last refill

	// Statistics
	TotalPackets uint64
	TotalBytes   uint64
	Violations   uint32

	// Blacklist state
	Blacklisted    bool
	BlacklistUntil int64 // unix nano — auto-unban after this time
}

// NewFlowBucket creates a new token bucket with specified limits.
func NewFlowBucket(maxPPS, maxBPS float64) *FlowBucket {
	now := time.Now().UnixNano()
	return &FlowBucket{
		PacketTokens: maxPPS, // Start full
		MaxPPS:       maxPPS,
		ByteTokens:   maxBPS,
		MaxBPS:       maxBPS,
		LastRefill:   now,
	}
}

// Allow checks if a packet of the given size should be allowed.
func (fb *FlowBucket) Allow(packetSize uint16) bool {
	fb.mu.Lock()
	defer fb.mu.Unlock()

	now := time.Now().UnixNano()

	// Check blacklist first — fast path
	if fb.Blacklisted {
		if now < fb.BlacklistUntil {
			return false
		}
		// Blacklist expired — unban
		fb.Blacklisted = false
		fb.PacketTokens = fb.MaxPPS
		fb.ByteTokens = fb.MaxBPS
		fb.LastRefill = now
	}

	// Refill tokens based on elapsed time
	elapsed := float64(now-fb.LastRefill) / float64(time.Second)
	if elapsed > 0 {
		fb.PacketTokens += fb.MaxPPS * elapsed
		if fb.PacketTokens > fb.MaxPPS*2 { // Allow burst up to 2x
			fb.PacketTokens = fb.MaxPPS * 2
		}

		fb.ByteTokens += fb.MaxBPS * elapsed
		if fb.ByteTokens > fb.MaxBPS*2 {
			fb.ByteTokens = fb.MaxBPS * 2
		}

		fb.LastRefill = now
	}

	// Check PPS limit
	if fb.PacketTokens < 1.0 {
		fb.Violations++
		return false
	}

	// Check BPS limit
	size := float64(packetSize)
	if fb.ByteTokens < size {
		fb.Violations++
		return false
	}

	// Consume tokens
	fb.PacketTokens -= 1.0
	fb.ByteTokens -= size

	// Track stats
	fb.TotalPackets++
	fb.TotalBytes += uint64(packetSize)

	return true
}

// Blacklist marks this flow as blacklisted for the given duration.
func (fb *FlowBucket) Blacklist(duration time.Duration) {
	fb.mu.Lock()
	defer fb.mu.Unlock()
	fb.Blacklisted = true
	fb.BlacklistUntil = time.Now().Add(duration).UnixNano()
}

// IsBlacklisted returns true if the flow is currently blacklisted.
func (fb *FlowBucket) IsBlacklisted() bool {
	fb.mu.Lock()
	defer fb.mu.Unlock()
	if !fb.Blacklisted {
		return false
	}
	if time.Now().UnixNano() >= fb.BlacklistUntil {
		fb.Blacklisted = false
		return false
	}
	return true
}

// IPBucket tracks aggregate traffic per-IP (all flows from same IP combined).
type IPBucket struct {
	mu sync.Mutex

	PacketTokens   float64
	MaxPPS         float64
	LastRefill     int64
	Violations     uint32
	Blacklisted    bool
	BlacklistUntil int64
}

// NewIPBucket creates a per-IP rate limiter.
func NewIPBucket(maxPPS float64) *IPBucket {
	now := time.Now().UnixNano()
	return &IPBucket{
		PacketTokens: maxPPS,
		MaxPPS:       maxPPS,
		LastRefill:   now,
	}
}

// Allow checks if a packet should be allowed for this IP.
func (ib *IPBucket) Allow() bool {
	ib.mu.Lock()
	defer ib.mu.Unlock()

	now := time.Now().UnixNano()

	if ib.Blacklisted {
		if now < ib.BlacklistUntil {
			return false
		}
		ib.Blacklisted = false
		ib.PacketTokens = ib.MaxPPS
		ib.LastRefill = now
	}

	elapsed := float64(now-ib.LastRefill) / float64(time.Second)
	if elapsed > 0 {
		ib.PacketTokens += ib.MaxPPS * elapsed
		if ib.PacketTokens > ib.MaxPPS*2 {
			ib.PacketTokens = ib.MaxPPS * 2
		}
		ib.LastRefill = now
	}

	if ib.PacketTokens < 1.0 {
		ib.Violations++
		return false
	}

	ib.PacketTokens -= 1.0
	return true
}

// Blacklist marks this IP as blacklisted.
func (ib *IPBucket) Blacklist(duration time.Duration) {
	ib.mu.Lock()
	defer ib.mu.Unlock()
	ib.Blacklisted = true
	ib.BlacklistUntil = time.Now().Add(duration).UnixNano()
}

// IsBlacklisted returns true if this IP is currently blacklisted.
func (ib *IPBucket) IsBlacklisted() bool {
	ib.mu.Lock()
	defer ib.mu.Unlock()
	if !ib.Blacklisted {
		return false
	}
	if time.Now().UnixNano() >= ib.BlacklistUntil {
		ib.Blacklisted = false
		return false
	}
	return true
}

// SubnetBucket tracks aggregate traffic per /24 subnet (e.g. 192.168.1.0/24).
// This defeats distributed botnets where thousands of bots are packed in the same subnet
// or rented VPS IP ranges.
type SubnetBucket struct {
	mu sync.Mutex

	PacketTokens   float64
	MaxPPS         float64
	LastRefill     int64
	Violations     uint32
	Blacklisted    bool
	BlacklistUntil int64
}

// NewSubnetBucket creates a per-subnet (/24) rate limiter.
func NewSubnetBucket(maxPPS float64) *SubnetBucket {
	now := time.Now().UnixNano()
	return &SubnetBucket{
		PacketTokens: maxPPS,
		MaxPPS:       maxPPS,
		LastRefill:   now,
	}
}

// Allow checks if a packet should be allowed for this /24 subnet.
func (sb *SubnetBucket) Allow() bool {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	now := time.Now().UnixNano()

	if sb.Blacklisted {
		if now < sb.BlacklistUntil {
			return false
		}
		sb.Blacklisted = false
		sb.PacketTokens = sb.MaxPPS
		sb.LastRefill = now
	}

	elapsed := float64(now-sb.LastRefill) / float64(time.Second)
	if elapsed > 0 {
		sb.PacketTokens += sb.MaxPPS * elapsed
		if sb.PacketTokens > sb.MaxPPS*2 {
			sb.PacketTokens = sb.MaxPPS * 2
		}
		sb.LastRefill = now
	}

	if sb.PacketTokens < 1.0 {
		sb.Violations++
		return false
	}

	sb.PacketTokens -= 1.0
	return true
}

// Blacklist marks this subnet as blacklisted.
func (sb *SubnetBucket) Blacklist(duration time.Duration) {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	sb.Blacklisted = true
	sb.BlacklistUntil = time.Now().Add(duration).UnixNano()
}

// IsBlacklisted returns true if this subnet is currently blacklisted.
func (sb *SubnetBucket) IsBlacklisted() bool {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	if !sb.Blacklisted {
		return false
	}
	if time.Now().UnixNano() >= sb.BlacklistUntil {
		sb.Blacklisted = false
		return false
	}
	return true
}


