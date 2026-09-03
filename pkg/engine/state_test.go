package engine

import (
	"testing"
	"time"

	"waf-game/pkg/packet"
)

func TestStateManager_Transitions(t *testing.T) {
	// Trigger at 100 PPS or 10000 BPS. Cooldown 1s.
	sm := NewStateManager(100, 10000, 1)

	warCalled := 0
	peaceCalled := 0
	sm.SetCallbacks(
		func() { warCalled++ },
		func() { peaceCalled++ },
	)

	if sm.GetMode() != ModePeace {
		t.Errorf("Expected initial mode Peace, got %v", sm.GetMode())
	}

	// 1. Under thresholds - should stay Peace
	sm.RecordPacket(50)
	sm.RecordPacket(50)
	sm.Evaluate()
	if sm.GetMode() != ModePeace || warCalled != 0 {
		t.Errorf("Should stay Peace. Mode: %v, warCalled: %d", sm.GetMode(), warCalled)
	}

	// 2. PPS exceeds threshold -> War Mode
	for i := 0; i < 105; i++ {
		sm.RecordPacketDetails(50, uint32(i+1), packet.ProtoTCP, true, true)
	}
	sm.Evaluate()
	if sm.GetMode() != ModeWar || warCalled != 1 {
		t.Errorf("Should transition to War. Mode: %v, warCalled: %d", sm.GetMode(), warCalled)
	}

	// 3. Immediately evaluate with low traffic - should stay War because of cooldown
	sm.RecordPacket(10)
	sm.Evaluate()
	if sm.GetMode() != ModeWar {
		t.Errorf("Should stay War due to cooldown")
	}

	// 4. Wait for cooldown, evaluate with low traffic -> Peace Mode
	time.Sleep(1100 * time.Millisecond)
	sm.RecordPacket(10) // 1 packet, well below triggerPPS/2
	sm.Evaluate()
	if sm.GetMode() != ModePeace || peaceCalled != 1 {
		t.Errorf("Should transition back to Peace. Mode: %v, peaceCalled: %d", sm.GetMode(), peaceCalled)
	}
}

func TestStateManagerDetectsDistributedBotnetBelowGlobalThreshold(t *testing.T) {
	sm := NewStateManager(4000, 30*1024*1024, 1)
	warCalled := 0
	sm.SetCallbacks(func() { warCalled++ }, func() {})

	// 1,000 UDP bots across 250 /24s: each bot sends only one packet, so
	// per-IP and per-/24 limiters alone cannot identify the campaign.
	for i := 0; i < 1000; i++ {
		ip := uint32(10)<<24 | uint32(i%250)<<16 | uint32(i/250)<<8 | uint32(i%253+1)
		sm.RecordPacketDetails(96, ip, packet.ProtoUDP, false, true)
	}
	sm.Evaluate()

	if !sm.IsBotnetDetected() || sm.GetMode() != ModeWar || warCalled != 1 {
		t.Fatalf("distributed botnet not escalated: detected=%v mode=%v unique_ip=%d subnet=%d", sm.IsBotnetDetected(), sm.GetMode(), sm.GetUniqueIPs(), sm.GetUniqueSubnets())
	}
	if sm.GetUniqueIPs() < 900 || sm.GetUniqueSubnets() < 200 {
		t.Fatalf("cardinality sketch unexpectedly inaccurate: ip=%d subnet=%d", sm.GetUniqueIPs(), sm.GetUniqueSubnets())
	}
}

func TestStateManagerDoesNotFlagVerifiedGamePopulationAsBotnet(t *testing.T) {
	sm := NewStateManager(15000, 50*1024*1024, 1)
	for i := 0; i < 20000; i++ {
		ip := uint32(10)<<24 | uint32(i%250)<<16 | uint32(i/250)<<8 | uint32(i%253+1)
		sm.RecordPacketDetails(128, ip, packet.ProtoUDP, false, false)
	}
	sm.Evaluate()
	if sm.IsBotnetDetected() || sm.IsWarMode() {
		t.Fatalf("verified game population caused false positive: botnet=%v mode=%v", sm.IsBotnetDetected(), sm.GetMode())
	}
}

func TestStateManager_ForceMode(t *testing.T) {
	sm := NewStateManager(100, 10000, 60)
	warCalled := 0
	peaceCalled := 0
	sm.SetCallbacks(
		func() { warCalled++ },
		func() { peaceCalled++ },
	)

	sm.ForceMode(ModeWar)
	if sm.GetMode() != ModeWar || warCalled != 1 {
		t.Errorf("ForceMode(ModeWar) failed")
	}
	if !sm.IsManual() {
		t.Errorf("Expected IsManual to be true after ForceMode")
	}

	sm.ForceMode(ModePeace)
	if sm.GetMode() != ModePeace || peaceCalled != 1 {
		t.Errorf("ForceMode(ModePeace) failed")
	}
}

func TestStateManager_ManualOverride(t *testing.T) {
	// Trigger at 100 PPS, Cooldown 1s.
	sm := NewStateManager(100, 10000, 1)

	warCalled := 0
	peaceCalled := 0
	sm.SetCallbacks(
		func() { warCalled++ },
		func() { peaceCalled++ },
	)

	// 1. Force War Mode (Manual override)
	sm.ForceMode(ModeWar)
	if sm.GetMode() != ModeWar || warCalled != 1 {
		t.Fatalf("Failed to force War Mode")
	}
	if !sm.IsManual() {
		t.Errorf("Expected IsManual to be true")
	}

	// 2. Wait for cooldown to expire
	time.Sleep(1100 * time.Millisecond)

	// 3. Evaluate with no traffic. Because it is manual, it should NOT de-escalate.
	sm.RecordPacket(0)
	sm.Evaluate()

	if sm.GetMode() != ModeWar || peaceCalled != 0 {
		t.Errorf("Should stay in War Mode because manual override is active. Got mode: %v, peaceCalled: %d", sm.GetMode(), peaceCalled)
	}

	// 4. Reset to auto
	sm.ResetToAuto()
	if sm.IsManual() {
		t.Errorf("Expected IsManual to be false after ResetToAuto")
	}

	// Because we just called ResetToAuto, it calls Evaluate() internally,
	// which should transition back to Peace since cooldown has elapsed and traffic is 0.
	if sm.GetMode() != ModePeace || peaceCalled != 1 {
		t.Errorf("Expected transition back to Peace mode after ResetToAuto. Got mode: %v, peaceCalled: %d", sm.GetMode(), peaceCalled)
	}
}
