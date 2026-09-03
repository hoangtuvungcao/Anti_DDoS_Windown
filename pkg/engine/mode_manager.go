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
	mode = sanitizeMode(mode)
	if m.currentMode == mode {
		m.mu.Unlock()
		return
	}

	m.currentMode = mode
	m.mu.Unlock()

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
	mode := m.GetMode()
	m.eng.cfgMu.RLock()
	cfg := m.eng.cfg
	m.eng.cfgMu.RUnlock()

	if udpShield != nil {
		switch mode {
		case ModeOff:
			m.eng.advancedEnforcement.Store(false)
			// OFF: disable all advanced protections, very permissive rate limits
			udpShield.SetDPI(false)
			udpShield.SetEntropy(false)
			udpShield.SetTwoWay(false)
			if udpShield.GameShield != nil {
				udpShield.GameShield.SetEnabled(false)
			}
			udpShield.SetRateLimits(1000000, 1000000000, 1000000, 1000000)

		case ModeOn:
			m.eng.advancedEnforcement.Store(true)
			// ON: maximum protection
			udpShield.SetDPI(cfg.WarEnableDPI)
			udpShield.SetEntropy(true)
			udpShield.SetTwoWay(cfg.TwoWayVerify)
			if udpShield.GameShield != nil {
				udpShield.GameShield.SetEnabled(true)
			}
			// Strict War-level rate limits
			udpShield.SetRateLimits(cfg.WarFlowPPS, cfg.WarFlowBPS, cfg.WarIPPPS, cfg.WarSubnetPPS)

		default: // AUTO
			if isWar {
				m.eng.advancedEnforcement.Store(true)
				udpShield.SetDPI(cfg.WarEnableDPI)
				entropyMode := int(m.eng.entropyMode.Load())
				if entropyMode == EntropyModeOn || entropyMode == EntropyModeAuto {
					udpShield.SetEntropy(true)
				} else {
					udpShield.SetEntropy(false)
				}
				udpShield.SetTwoWay(cfg.TwoWayVerify)
				if udpShield.GameShield != nil {
					udpShield.GameShield.SetEnabled(true)
				}
				udpShield.SetRateLimits(cfg.WarFlowPPS, cfg.WarFlowBPS, cfg.WarIPPPS, cfg.WarSubnetPPS)
			} else {
				m.eng.advancedEnforcement.Store(!cfg.PeaceMonitorOnly)
				udpShield.SetDPI(cfg.EnableDPIShield)
				if int(m.eng.entropyMode.Load()) == EntropyModeOn {
					udpShield.SetEntropy(true)
				} else {
					udpShield.SetEntropy(false)
				}
				udpShield.SetTwoWay(false)
				if udpShield.GameShield != nil {
					udpShield.GameShield.SetEnabled(true)
				}
				udpShield.SetRateLimits(cfg.UDPFlowPPS, cfg.UDPFlowBPS, cfg.UDPPerIPPPS, cfg.SubnetPPS)
			}
		}
	}

	if udpShield != nil {
		switch mode {
		case ModeOff:
			udpShield.SetStrict(false)
		case ModeOn:
			udpShield.SetStrict(true)
		default: // AUTO
			udpShield.SetStrict(isWar)
		}
	}

	if tcpShield != nil {
		switch mode {
		case ModeOff:
			tcpShield.SetStrict(false)
		case ModeOn:
			tcpShield.SetStrict(true)
		default: // AUTO
			tcpShield.SetStrict(isWar)
		}
	}
}

// ApplyCurrent applies the configured mode at startup even when it has not changed.
func (m *ModeManager) ApplyCurrent() {
	mode := m.GetMode()
	switch mode {
	case ModeOn:
		m.state.ForceMode(ModeWar)
		m.applyMode(true)
	case ModeOff:
		m.state.ForceMode(ModePeace)
		m.applyMode(false)
	default:
		m.state.ResetToAuto()
		m.applyMode(m.state.IsWarMode())
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
