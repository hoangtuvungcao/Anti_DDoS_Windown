package engine

import (
	"sync/atomic"
	"time"
)

// SystemMode represents the current protection mode
type SystemMode int32

const (
	ModePeace SystemMode = 0
	ModeWar   SystemMode = 1
)

// StateManager controls dynamic switching between Peace and War modes.
// Monitors total traffic volume and automatically escalates protection.
type StateManager struct {
	mode atomic.Int32 // 0=Peace, 1=War
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
// Called on every packet in the pipeline.
func (sm *StateManager) RecordPacket(size uint16) {
	sm.currentPPS.Add(1)
	sm.currentBPS.Add(uint64(size))
}

// Evaluate checks current traffic levels and switches mode if needed.
// Should be called once per second.
func (sm *StateManager) Evaluate() {
	pps := sm.currentPPS.Swap(0)
	bps := sm.currentBPS.Swap(0)

	// If in manual override, skip automatic evaluation/transitions.
	if sm.isManual.Load() {
		return
	}

	currentMode := SystemMode(sm.mode.Load())

	switch currentMode {
	case ModePeace:
		// Check if we should escalate to War Mode
		if pps > sm.triggerPPS || bps > sm.triggerBPS {
			sm.mode.Store(int32(ModeWar))
			sm.warStartTime = time.Now().Unix()
			if sm.onWarMode != nil {
				sm.onWarMode()
			}
		}

	case ModeWar:
		// Check if we should de-escalate to Peace Mode
		elapsed := time.Now().Unix() - sm.warStartTime
		if elapsed >= sm.cooldownSec && pps <= sm.triggerPPS/2 && bps <= sm.triggerBPS/2 {
			sm.mode.Store(int32(ModePeace))
			if sm.onPeaceMode != nil {
				sm.onPeaceMode()
			}
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

	if mode == ModeWar {
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

// IsWarMode returns true if currently in War Mode.
func (sm *StateManager) IsWarMode() bool {
	return sm.mode.Load() == int32(ModeWar)
}

// GetCurrentPPS returns the PPS from the last evaluation window.
func (sm *StateManager) GetCurrentPPS() uint64 {
	return sm.currentPPS.Load()
}

// GetCurrentBPS returns the BPS from the last evaluation window.
func (sm *StateManager) GetCurrentBPS() uint64 {
	return sm.currentBPS.Load()
}
