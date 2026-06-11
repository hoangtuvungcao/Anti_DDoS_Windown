package datastore

import (
	"time"
)

// FlowBucket implements Token Bucket rate limiting for a single flow.
// Tracks both PPS (packets per second) and BPS (bytes per second).
type FlowBucket struct {
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

	// Blacklist state
	Blacklisted    bool
	BlacklistUntil int64 // unix nano — auto-unban after this time
}

// NewFlowBucket creates a new token bucket with specified limits.
func NewFlowBucket(maxPPS, maxBPS float64) FlowBucket {
	now := time.Now().UnixNano()
	return FlowBucket{
		PacketTokens: maxPPS,  // Start full
		MaxPPS:       maxPPS,
		ByteTokens:   maxBPS,
		MaxBPS:       maxBPS,
		LastRefill:   now,
	}
}

// Allow checks if a packet of the given size should be allowed.
// Returns true if allowed, false if rate exceeded.
// Updates internal state (refills tokens, decrements).
func (fb *FlowBucket) Allow(packetSize uint16) bool {
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
		return false
	}

	// Check BPS limit
	size := float64(packetSize)
	if fb.ByteTokens < size {
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
	fb.Blacklisted = true
	fb.BlacklistUntil = time.Now().Add(duration).UnixNano()
}

// IsBlacklisted returns true if the flow is currently blacklisted.
func (fb *FlowBucket) IsBlacklisted() bool {
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
	PacketTokens float64
	MaxPPS       float64
	LastRefill   int64
	Blacklisted    bool
	BlacklistUntil int64
}

// NewIPBucket creates a per-IP rate limiter.
func NewIPBucket(maxPPS float64) IPBucket {
	now := time.Now().UnixNano()
	return IPBucket{
		PacketTokens: maxPPS,
		MaxPPS:       maxPPS,
		LastRefill:   now,
	}
}

// Allow checks if a packet should be allowed for this IP.
func (ib *IPBucket) Allow() bool {
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
		return false
	}

	ib.PacketTokens -= 1.0
	return true
}

// Blacklist marks this IP as blacklisted.
func (ib *IPBucket) Blacklist(duration time.Duration) {
	ib.Blacklisted = true
	ib.BlacklistUntil = time.Now().Add(duration).UnixNano()
}

// IsBlacklisted returns true if this IP is currently blacklisted.
func (ib *IPBucket) IsBlacklisted() bool {
	if !ib.Blacklisted {
		return false
	}
	if time.Now().UnixNano() >= ib.BlacklistUntil {
		ib.Blacklisted = false
		return false
	}
	return true
}
