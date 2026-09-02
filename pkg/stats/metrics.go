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
	ReflectionDrops atomic.Uint64 // UDP amplification/reflection attacks
	SubnetDrops     atomic.Uint64 // /24 Subnet flood drops
	OutOfStateDrops atomic.Uint64 // Out-of-state TCP (ACK/FIN/RST flood)
	GameQueryDrops  atomic.Uint64 // Malformed or flooded game queries
	EntropyDrops    atomic.Uint64 // Suspicious random/repeated UDP payloads
	UnverifiedDrops atomic.Uint64 // Failed two-way verification
	WhitelistHits   atomic.Uint64 // Whitelist passes

	// State
	ActiveFlows     atomic.Uint64
	BlacklistedIPs  atomic.Uint64
	VerifiedTCP     atomic.Uint64
	UniqueSourceIPs atomic.Uint64
	UniqueSubnets   atomic.Uint64
	BotnetDetected  atomic.Bool

	// Mode & Threat: 0=Peace, 1=Elevated, 2=War, 3=Under Siege
	CurrentMode atomic.Int32
	ThreatLevel atomic.Int32
	WarStart    atomic.Int64

	// Snapshot values (set by Snapshot())
	SnapPPS        atomic.Uint64
	SnapBPS        atomic.Uint64
	SnapOutPPS     atomic.Uint64
	SnapOutBPS     atomic.Uint64
	SnapDropPPS    atomic.Uint64
	SnapDropBPS    atomic.Uint64
	SnapL0         atomic.Uint64
	SnapL1         atomic.Uint64
	SnapL2         atomic.Uint64
	SnapL3         atomic.Uint64
	SnapL4         atomic.Uint64
	SnapReflection atomic.Uint64
	SnapSubnet     atomic.Uint64
	SnapOutOfState atomic.Uint64
	SnapGameQuery  atomic.Uint64
	SnapEntropy    atomic.Uint64
	SnapUnverified atomic.Uint64
	SnapWhitelist  atomic.Uint64
}

// NewMetrics creates a new metrics instance.
func NewMetrics() *Metrics {
	return &Metrics{}
}

// Snapshot captures current values and resets PPS/BPS counters.
// Should be called exactly once per second by the engine state evaluator.
func (m *Metrics) Snapshot() {
	m.SnapPPS.Store(m.InboundPPS.Swap(0))
	m.SnapBPS.Store(m.InboundBPS.Swap(0))
	m.SnapOutPPS.Store(m.OutboundPPS.Swap(0))
	m.SnapOutBPS.Store(m.OutboundBPS.Swap(0))
	m.SnapDropPPS.Store(m.DroppedPPS.Swap(0))
	m.SnapDropBPS.Store(m.DroppedBPS.Swap(0))
	m.SnapL0.Store(m.Layer0Drops.Swap(0))
	m.SnapL1.Store(m.Layer1Drops.Swap(0))
	m.SnapL2.Store(m.Layer2Drops.Swap(0))
	m.SnapL3.Store(m.Layer3Drops.Swap(0))
	m.SnapL4.Store(m.Layer4Drops.Swap(0))
	m.SnapReflection.Store(m.ReflectionDrops.Swap(0))
	m.SnapSubnet.Store(m.SubnetDrops.Swap(0))
	m.SnapOutOfState.Store(m.OutOfStateDrops.Swap(0))
	m.SnapGameQuery.Store(m.GameQueryDrops.Swap(0))
	m.SnapEntropy.Store(m.EntropyDrops.Swap(0))
	m.SnapUnverified.Store(m.UnverifiedDrops.Swap(0))
	m.SnapWhitelist.Store(m.WhitelistHits.Swap(0))
}

// TotalDrops returns total drops across all layers in the last snapshot.
func (m *Metrics) TotalDrops() uint64 {
	return m.SnapL0.Load() + m.SnapL1.Load() + m.SnapL2.Load() + m.SnapL3.Load() + m.SnapL4.Load()
}
