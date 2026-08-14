package stats

import (
	"sync/atomic"
)

// Metrics holds all firewall statistics using atomic operations.
// Zero lock contention — safe to read/write from any goroutine.
type Metrics struct {
	// Global traffic
	InboundPPS  atomic.Uint64
	InboundBPS  atomic.Uint64
	OutboundPPS atomic.Uint64
	OutboundBPS atomic.Uint64
	DroppedPPS  atomic.Uint64
	DroppedBPS  atomic.Uint64

	// Per-layer drop counters
	Layer0Drops atomic.Uint64 // Static & dynamic Blacklist
	Layer1Drops atomic.Uint64 // Garbage filter & RFC violations
	Layer2Drops atomic.Uint64 // Port not listening
	Layer3Drops atomic.Uint64 // TCP shield drops
	Layer4Drops atomic.Uint64 // UDP rate limit drops

	// Specialized attack drop counters
	ReflectionDrops  atomic.Uint64 // UDP amplification/reflection attacks
	SubnetDrops      atomic.Uint64 // /24 Subnet flood drops
	OutOfStateDrops  atomic.Uint64 // Out-of-state TCP (ACK/FIN/RST flood)
	GameQueryDrops   atomic.Uint64 // Malformed or flooded game queries
	WhitelistHits    atomic.Uint64 // Whitelist passes

	// State
	ActiveFlows    atomic.Uint64
	BlacklistedIPs atomic.Uint64
	VerifiedTCP    atomic.Uint64

	// Mode & Threat: 0=Peace, 1=Elevated, 2=War, 3=Under Siege
	CurrentMode atomic.Int32
	ThreatLevel atomic.Int32
	WarStart    atomic.Int64

	// Snapshot values (set by Snapshot())
	SnapPPS          uint64
	SnapBPS          uint64
	SnapOutPPS       uint64
	SnapOutBPS       uint64
	SnapDropPPS      uint64
	SnapDropBPS      uint64
	SnapL0           uint64
	SnapL1           uint64
	SnapL2           uint64
	SnapL3           uint64
	SnapL4           uint64
	SnapReflection   uint64
	SnapSubnet       uint64
	SnapOutOfState   uint64
	SnapGameQuery    uint64
	SnapWhitelist    uint64
}

// NewMetrics creates a new metrics instance.
func NewMetrics() *Metrics {
	return &Metrics{}
}

// Snapshot captures current values and resets PPS/BPS counters.
// Should be called exactly once per second by the CLI goroutine.
func (m *Metrics) Snapshot() {
	m.SnapPPS = m.InboundPPS.Swap(0)
	m.SnapBPS = m.InboundBPS.Swap(0)
	m.SnapOutPPS = m.OutboundPPS.Swap(0)
	m.SnapOutBPS = m.OutboundBPS.Swap(0)
	m.SnapDropPPS = m.DroppedPPS.Swap(0)
	m.SnapDropBPS = m.DroppedBPS.Swap(0)

	m.SnapL0 = m.Layer0Drops.Swap(0)
	m.SnapL1 = m.Layer1Drops.Swap(0)
	m.SnapL2 = m.Layer2Drops.Swap(0)
	m.SnapL3 = m.Layer3Drops.Swap(0)
	m.SnapL4 = m.Layer4Drops.Swap(0)
	m.SnapReflection = m.ReflectionDrops.Swap(0)
	m.SnapSubnet = m.SubnetDrops.Swap(0)
	m.SnapOutOfState = m.OutOfStateDrops.Swap(0)
	m.SnapGameQuery = m.GameQueryDrops.Swap(0)
	m.SnapWhitelist = m.WhitelistHits.Swap(0)
}

// TotalDrops returns total drops across all layers in the last snapshot.
func (m *Metrics) TotalDrops() uint64 {
	return m.SnapL0 + m.SnapL1 + m.SnapL2 + m.SnapL3 + m.SnapL4
}

