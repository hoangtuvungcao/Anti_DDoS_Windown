package engine

import (
	"sync/atomic"
	"time"
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
	lastReset  int64

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
		lastReset:   time.Now().Unix(),
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

// Evaluate checks current traffic levels and switches mode if needed.
func (sm *StateManager) Evaluate() {
	pps := sm.currentPPS.Swap(0)
	bps := sm.currentBPS.Swap(0)

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

	case pps >= sm.triggerPPS || bps >= sm.triggerBPS:
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

// ResetToAuto releases manual override and triggers immediate evaluation.
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
	return sm.currentPPS.Load()
}

// GetCurrentBPS returns the BPS from the last evaluation window.
func (sm *StateManager) GetCurrentBPS() uint64 {
	return sm.currentBPS.Load()
}

