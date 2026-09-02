package engine

import (
	"math/bits"
	"sync/atomic"
	"time"

	"waf-game/pkg/packet"
)

const (
	ipSketchWords     = 1024 // 65,536-bit lock-free cardinality sketch
	subnetSketchWords = 256  // 16,384-bit sketch
)

// SystemMode represents the current protection mode
type SystemMode int32

const (
	ModePeace      SystemMode = 0
	ModeElevated   SystemMode = 1
	ModeWar        SystemMode = 2
	ModeUnderSiege SystemMode = 3
)

// StateManager controls dynamic switching between Peace, Elevated, War, and Under Siege modes.
type StateManager struct {
	mode     atomic.Int32 // 0=Peace, 1=Elevated, 2=War, 3=UnderSiege
	isManual atomic.Bool  // true if manually overridden

	// Trigger thresholds
	triggerPPS uint64
	triggerBPS uint64

	// Cooldown
	cooldownSec  int64
	warStartTime int64

	// Traffic tracking (1-second window)
	currentPPS atomic.Uint64
	currentBPS atomic.Uint64
	lastPPS    atomic.Uint64
	lastBPS    atomic.Uint64
	udpPackets atomic.Uint64
	synPackets atomic.Uint64
	ipSketch   [ipSketchWords]atomic.Uint64
	subSketch  [subnetSketchWords]atomic.Uint64
	uniqueIPs  atomic.Uint64
	uniqueNets atomic.Uint64
	botnet     atomic.Bool

	// Callbacks for mode transitions
	onWarMode   func()
	onPeaceMode func()
}

// NewStateManager creates a new dynamic state manager.
func NewStateManager(triggerPPS, triggerBPS uint64, cooldownSec int64) *StateManager {
	if triggerPPS == 0 {
		triggerPPS = 5000
	}
	if triggerBPS == 0 {
		triggerBPS = 52428800 // 50 MB/s
	}
	if cooldownSec == 0 {
		cooldownSec = 60
	}

	return &StateManager{
		triggerPPS:  triggerPPS,
		triggerBPS:  triggerBPS,
		cooldownSec: cooldownSec,
	}
}

// SetCallbacks sets mode transition callbacks
func (sm *StateManager) SetCallbacks(onWar, onPeace func()) {
	sm.onWarMode = onWar
	sm.onPeaceMode = onPeace
}

// RecordPacket records an incoming packet for traffic monitoring.
func (sm *StateManager) RecordPacket(size uint16) {
	sm.currentPPS.Add(1)
	sm.currentBPS.Add(uint64(size))
}

// RecordPacketDetails records traffic before filtering and feeds the distributed
// botnet detector. Fixed-size atomic sketches avoid a global lock on the hot path.
func (sm *StateManager) RecordPacketDetails(size uint16, srcIP uint32, protocol uint8, syn bool) {
	sm.RecordPacket(size)
	if protocol == packet.ProtoUDP {
		sm.udpPackets.Add(1)
	}
	if protocol == packet.ProtoTCP && syn {
		sm.synPackets.Add(1)
	}
	ipHash := mix32(srcIP) % uint32(ipSketchWords*64)
	sm.ipSketch[ipHash>>6].Or(uint64(1) << (ipHash & 63))
	subHash := mix32(srcIP>>8) % uint32(subnetSketchWords*64)
	sm.subSketch[subHash>>6].Or(uint64(1) << (subHash & 63))
}

func mix32(v uint32) uint32 {
	v ^= v >> 16
	v *= 0x7feb352d
	v ^= v >> 15
	v *= 0x846ca68b
	return v ^ (v >> 16)
}

// Evaluate checks current traffic levels and switches mode if needed.
func (sm *StateManager) Evaluate() {
	pps := sm.currentPPS.Swap(0)
	bps := sm.currentBPS.Swap(0)
	udp := sm.udpPackets.Swap(0)
	syn := sm.synPackets.Swap(0)
	sm.lastPPS.Store(pps)
	sm.lastBPS.Store(bps)

	var ipBits, subnetBits uint64
	for i := range sm.ipSketch {
		ipBits += uint64(bits.OnesCount64(sm.ipSketch[i].Swap(0)))
	}
	for i := range sm.subSketch {
		subnetBits += uint64(bits.OnesCount64(sm.subSketch[i].Swap(0)))
	}
	sm.uniqueIPs.Store(ipBits)
	sm.uniqueNets.Store(subnetBits)
	protocolFlood := udp*10 >= pps*6 || syn*10 >= pps*4
	// Distributed botnet requires broad cardinality (>= 500 IPs across >= 150 subnets)
	distributedBotnet := pps >= 1000 && ipBits >= 500 && subnetBits >= 150 && protocolFlood
	sm.botnet.Store(distributedBotnet)

	if sm.isManual.Load() {
		return
	}

	currentMode := SystemMode(sm.mode.Load())

	// Dynamic multi-stage evaluation
	switch {
	case pps >= sm.triggerPPS*3 || bps >= sm.triggerBPS*3:
		// Under Siege level
		if currentMode != ModeUnderSiege {
			sm.mode.Store(int32(ModeUnderSiege))
			sm.warStartTime = time.Now().Unix()
			if sm.onWarMode != nil {
				sm.onWarMode()
			}
		}

	case pps >= sm.triggerPPS || bps >= sm.triggerBPS || distributedBotnet:
		// War level
		if currentMode != ModeWar && currentMode != ModeUnderSiege {
			sm.mode.Store(int32(ModeWar))
			sm.warStartTime = time.Now().Unix()
			if sm.onWarMode != nil {
				sm.onWarMode()
			}
		}

	case pps >= sm.triggerPPS/2 || bps >= sm.triggerBPS/2:
		// Elevated level
		if currentMode == ModePeace {
			sm.mode.Store(int32(ModeElevated))
		}

	default:
		// Traffic is low — check cooldown before de-escalating
		if currentMode >= ModeWar {
			elapsed := time.Now().Unix() - sm.warStartTime
			if elapsed >= sm.cooldownSec && pps <= sm.triggerPPS/3 && bps <= sm.triggerBPS/3 {
				sm.mode.Store(int32(ModePeace))
				if sm.onPeaceMode != nil {
					sm.onPeaceMode()
				}
			}
		} else if currentMode == ModeElevated {
			sm.mode.Store(int32(ModePeace))
		}
	}
}

// GetMode returns the current system mode.
func (sm *StateManager) GetMode() SystemMode {
	return SystemMode(sm.mode.Load())
}

// ForceMode manually sets the system mode and locks it (manual override).
func (sm *StateManager) ForceMode(mode SystemMode) {
	sm.isManual.Store(true)
	old := SystemMode(sm.mode.Swap(int32(mode)))
	if old == mode {
		return
	}

	if mode >= ModeWar {
		sm.warStartTime = time.Now().Unix()
		if sm.onWarMode != nil {
			sm.onWarMode()
		}
	} else {
		if sm.onPeaceMode != nil {
			sm.onPeaceMode()
		}
	}
}

// ResetToAuto releases manual override and triggers an immediate evaluation.
// NOTE: Evaluate() will Swap(0) currentPPS/currentBPS which resets the 1-second accumulator.
// This is acceptable here since the user explicitly changed mode \u2014 a clean-slate evaluation
// is preferred over waiting up to 1 second for the next stateEvaluator tick.
func (sm *StateManager) ResetToAuto() {
	sm.isManual.Store(false)
	sm.Evaluate()
}

// IsManual returns true if the system is currently under manual override.
func (sm *StateManager) IsManual() bool {
	return sm.isManual.Load()
}

// IsWarMode returns true if currently in War Mode or Under Siege.
func (sm *StateManager) IsWarMode() bool {
	return sm.mode.Load() >= int32(ModeWar)
}

// GetCurrentPPS returns the PPS from the last evaluation window.
func (sm *StateManager) GetCurrentPPS() uint64 {
	return sm.lastPPS.Load()
}

// GetCurrentBPS returns the BPS from the last evaluation window.
func (sm *StateManager) GetCurrentBPS() uint64 {
	return sm.lastBPS.Load()
}

func (sm *StateManager) IsBotnetDetected() bool   { return sm.botnet.Load() }
func (sm *StateManager) GetUniqueIPs() uint64     { return sm.uniqueIPs.Load() }
func (sm *StateManager) GetUniqueSubnets() uint64 { return sm.uniqueNets.Load() }
