package engine

import (
	"testing"
	"time"
)

func TestSetSameAutoModeReappliesCurrentWarPolicy(t *testing.T) {
	state := NewStateManager(100, 10_000, 60)
	eng := &Engine{
		cfg: EngineConfig{
			PeaceMonitorOnly: true,
			UDPFlowPPS:       500, UDPFlowBPS: 5 * 1024 * 1024,
			UDPPerIPPPS: 1500, SubnetPPS: 5000,
			WarFlowPPS: 250, WarFlowBPS: 2 * 1024 * 1024,
			WarIPPPS: 600, WarSubnetPPS: 2500,
			WarEnableDPI: true, TwoWayVerify: true,
		},
		state:     state,
		udpShield: NewUDPShield(500, 5*1024*1024, 1500, 5000, 30*time.Second, nil),
		tcpShield: NewTCPShield(nil, 150, 60, 500, 90),
	}
	eng.modeManager = NewModeManager(ModeAuto, state, eng)
	state.mode.Store(int32(ModeWar))

	// Simulate a preset mutating live shields immediately before it asks for
	// AUTO again, which is the sequence used by the dashboard.
	eng.udpShield.SetRateLimits(500, 5*1024*1024, 1500, 5000)
	eng.tcpShield.SetStrict(false)
	eng.modeManager.SetMode(ModeAuto)

	if !eng.IsAdvancedEnforcementEnabled() || eng.udpShield.GetFlowPPS() != 250 {
		t.Fatalf("same-mode AUTO did not restore WAR UDP policy: advanced=%v flow=%v",
			eng.IsAdvancedEnforcementEnabled(), eng.udpShield.GetFlowPPS())
	}
	eng.tcpShield.mu.RLock()
	strict := eng.tcpShield.strict
	eng.tcpShield.mu.RUnlock()
	if !strict {
		t.Fatal("same-mode AUTO left TCP strict mode disabled during WAR")
	}
}

func TestMonitorOnlyPeaceEnforcesOnlyAfterWar(t *testing.T) {
	state := NewStateManager(15000, 50*1024*1024, 60)
	eng := &Engine{
		cfg: EngineConfig{
			PeaceMonitorOnly: true,
			UDPFlowPPS:       500,
			UDPFlowBPS:       5 * 1024 * 1024,
			UDPPerIPPPS:      1500,
			SubnetPPS:        5000,
			WarFlowPPS:       250,
			WarFlowBPS:       2 * 1024 * 1024,
			WarIPPPS:         600,
			WarSubnetPPS:     2500,
			WarEnableDPI:     true,
			TwoWayVerify:     true,
		},
		state:     state,
		udpShield: NewUDPShield(500, 5*1024*1024, 1500, 5000, 30*time.Second, nil),
		tcpShield: NewTCPShield(nil, 150, 60, 500, 90),
	}
	eng.modeManager = NewModeManager(ModeAuto, state, eng)
	eng.modeManager.ApplyCurrent()
	if eng.IsAdvancedEnforcementEnabled() {
		t.Fatal("AUTO peace must remain monitor-only")
	}

	eng.modeManager.SetMode(ModeOn)
	if !eng.IsAdvancedEnforcementEnabled() {
		t.Fatal("WAR mode must enable advanced enforcement")
	}
	if eng.udpShield.IsEntropyEnabled() {
		t.Fatal("forced WAR ignored entropy_mode=OFF")
	}

	eng.ConfigurePeaceUDP(700, 6*1024*1024, 1800, 6000, false, true)
	eng.modeManager.SetMode(ModeAuto)
	if eng.IsAdvancedEnforcementEnabled() {
		t.Fatal("returning to AUTO peace must disable enforcement")
	}
	if got := eng.udpShield.GetFlowPPS(); got != 700 {
		t.Fatalf("peace preset did not persist across mode transition: got %v", got)
	}
}
