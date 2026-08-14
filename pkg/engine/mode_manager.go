package engine

import (
	"sync"
)

// Mode constants
const (
	ModeAuto = "AUTO"
	ModeOn   = "ON"
	ModeOff  = "OFF"
)

// ModeManager centralizes the logic for Auto/On/Off system modes.
// It is the single source of truth for which engine features are active.
type ModeManager struct {
	mu          sync.RWMutex
	currentMode string
	state       *StateManager
	eng         *Engine
}

// NewModeManager initializes a new ModeManager.
func NewModeManager(initialMode string, state *StateManager, eng *Engine) *ModeManager {
	if initialMode == "" {
		initialMode = ModeAuto
	}
	mm := &ModeManager{
		currentMode: sanitizeMode(initialMode),
		state:       state,
		eng:         eng,
	}
	return mm
}

// SetMode updates the system mode and triggers state changes accordingly.
func (m *ModeManager) SetMode(mode string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	mode = sanitizeMode(mode)
	if m.currentMode == mode {
		return
	}

	m.currentMode = mode

	switch mode {
	case ModeOn:
		// ON = Force War Mode + all protections active
		m.state.ForceMode(ModeWar)
		m.applyMode(true)
	case ModeOff:
		// OFF = Force Peace Mode + minimal protections
		m.state.ForceMode(ModePeace)
		m.applyMode(false)
	default:
		// AUTO = Let StateManager handle transitions dynamically
		m.state.ResetToAuto()
		m.applyMode(m.state.IsWarMode())
	}
}

// CycleMode cycles through AUTO -> ON -> OFF -> AUTO and returns the new mode.
func (m *ModeManager) CycleMode() string {
	m.mu.RLock()
	current := m.currentMode
	m.mu.RUnlock()

	var next string
	switch current {
	case ModeAuto:
		next = ModeOn
	case ModeOn:
		next = ModeOff
	case ModeOff:
		next = ModeAuto
	default:
		next = ModeAuto
	}

	m.SetMode(next)
	return next
}

// applyMode syncs all engine subsystems to match the current protection level.
func (m *ModeManager) applyMode(isWar bool) {
	if m.eng == nil {
		return
	}
	udpShield := m.eng.GetUDPShield()
	tcpShield := m.eng.GetTCPShield()

	if udpShield != nil {
		switch m.currentMode {
		case ModeOff:
			// OFF: disable all advanced protections, very permissive rate limits
			udpShield.SetDPI(false)
			udpShield.SetEntropy(false)
			udpShield.SetTwoWay(false)
			if udpShield.GameShield != nil {
				udpShield.GameShield.SetEnabled(false)
			}
			udpShield.SetRateLimits(1000000, 1000000000, 1000000, 1000000)

		case ModeOn:
			// ON: maximum protection
			udpShield.SetDPI(true)
			udpShield.SetEntropy(true)
			udpShield.SetTwoWay(true)
			if udpShield.GameShield != nil {
				udpShield.GameShield.SetEnabled(true)
			}
			// Strict War-level rate limits
			udpShield.SetRateLimits(40, 524288, 100, 250)

		default: // AUTO
			if isWar {
				udpShield.SetDPI(true)
				if m.eng.entropyMode == EntropyModeOn || m.eng.entropyMode == EntropyModeAuto {
					udpShield.SetEntropy(true)
				} else {
					udpShield.SetEntropy(false)
				}
				udpShield.SetTwoWay(true)
				if udpShield.GameShield != nil {
					udpShield.GameShield.SetEnabled(true)
				}
				udpShield.SetRateLimits(40, 524288, 100, 250)
			} else {
				udpShield.SetDPI(false)
				if m.eng.entropyMode == EntropyModeOn {
					udpShield.SetEntropy(true)
				} else {
					udpShield.SetEntropy(false)
				}
				udpShield.SetTwoWay(false)
				if udpShield.GameShield != nil {
					udpShield.GameShield.SetEnabled(true)
				}
				udpShield.SetRateLimits(80, 1048576, 250, 500)
			}
		}
	}

	if tcpShield != nil {
		switch m.currentMode {
		case ModeOff:
			tcpShield.SetStrict(false)
		case ModeOn:
			tcpShield.SetStrict(true)
		default: // AUTO
			tcpShield.SetStrict(isWar)
		}
	}
}

// GetMode returns the current system mode.
func (m *ModeManager) GetMode() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.currentMode
}

func sanitizeMode(mode string) string {
	switch mode {
	case "on", "ON", "On", "war", "WAR", "War":
		return ModeOn
	case "off", "OFF", "Off", "peace", "PEACE", "Peace":
		return ModeOff
	default:
		return ModeAuto
	}
}


