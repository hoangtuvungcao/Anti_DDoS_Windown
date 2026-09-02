package engine

import (
	"testing"
	"time"

	"waf-game/pkg/stats"
)

func TestAutoDefense_AttackClassificationAndBaseline(t *testing.T) {
	metrics := stats.NewMetrics()
	ad := NewAutoDefense(metrics, nil)

	// In Peace mode, simulate normal 200 PPS baseline
	metrics.SnapPPS.Store(200)
	metrics.SnapBPS.Store(200 * 500)
	recPPS, recBPS := ad.EvaluateBaselineAndUpdate(false)

	if recPPS < 2500 {
		t.Errorf("Expected min recommended trigger PPS to be at least 2500, got %d", recPPS)
	}
	if recBPS < 26214400 {
		t.Errorf("Expected min recommended trigger BPS to be at least 25MB/s, got %d", recBPS)
	}

	// In War mode, simulate Subnet DDoS
	metrics.SnapSubnet.Store(500)
	ad.EvaluateBaselineAndUpdate(true)

	if ad.GetPrimaryAttackVector() != VectorSubnetBotnet {
		t.Errorf("Expected VectorSubnetBotnet, got %s", ad.GetPrimaryAttackVector())
	}

	// Simulate Game Query DDoS
	metrics.SnapSubnet.Store(0)
	metrics.SnapGameQuery.Store(300)
	ad.EvaluateBaselineAndUpdate(true)

	if ad.GetPrimaryAttackVector() != VectorGameQueryFlood {
		t.Errorf("Expected VectorGameQueryFlood, got %s", ad.GetPrimaryAttackVector())
	}
}

func TestAutoDefense_GraduatedBan(t *testing.T) {
	metrics := stats.NewMetrics()
	ad := NewAutoDefense(metrics, nil)

	ipKey := uint64(0x01020304)

	// Offense 1: 60s
	dur1 := ad.CalculateGraduatedBan(ipKey)
	if dur1 != 60*time.Second {
		t.Errorf("Expected 60s on 1st offense, got %v", dur1)
	}

	// Offense 2: 5m
	dur2 := ad.CalculateGraduatedBan(ipKey)
	if dur2 != 5*time.Minute {
		t.Errorf("Expected 5m on 2nd offense, got %v", dur2)
	}

	// Offense 3: 1h
	dur3 := ad.CalculateGraduatedBan(ipKey)
	if dur3 != 1*time.Hour {
		t.Errorf("Expected 1h on 3rd offense, got %v", dur3)
	}

	// Offense 5: 24h
	_ = ad.CalculateGraduatedBan(ipKey) // 4th
	dur5 := ad.CalculateGraduatedBan(ipKey)
	if dur5 != 24*time.Hour {
		t.Errorf("Expected 24h on 5th offense, got %v", dur5)
	}
}

func TestAutoDefense_PortProfiles(t *testing.T) {
	metrics := stats.NewMetrics()
	ad := NewAutoDefense(metrics, nil)

	p27015 := ad.GetPortProfile(27015)
	if p27015 != "UNIVERSAL_PORT_SHIELD (Active 1-65535)" {
		t.Errorf("Expected UNIVERSAL_PORT_SHIELD for 27015, got %s", p27015)
	}

	pUnknown := ad.GetPortProfile(12345)
	if pUnknown != "UNIVERSAL_PORT_SHIELD (Active 1-65535)" {
		t.Errorf("Expected UNIVERSAL_PORT_SHIELD for unknown port, got %s", pUnknown)
	}
}

func TestAutoDefense_CarpetBombing(t *testing.T) {
	metrics := stats.NewMetrics()
	ad := NewAutoDefense(metrics, nil)

	// Simulate Carpet Bombing (heavy closed port scan across multiple subnets)
	metrics.SnapL2.Store(120)
	metrics.SnapSubnet.Store(60)

	ad.classifyAttackVector()
	primary := ad.GetPrimaryAttackVector()
	if primary != VectorCarpetBombing {
		t.Errorf("Expected primary vector %s, got %s", VectorCarpetBombing, primary)
	}
}
