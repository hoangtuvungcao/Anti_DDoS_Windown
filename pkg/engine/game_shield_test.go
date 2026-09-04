package engine

import (
	"testing"

	"waf-game/pkg/packet"
)

func TestGameShield_A2SQueryLimiting(t *testing.T) {
	gs := NewGameShield(nil)

	a2sPayload := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x54, 'S', 'o', 'u', 'r', 'c', 'e'}

	pkt := &packet.Packet{
		Protocol: packet.ProtoUDP,
		SrcIP:    [4]byte{192, 0, 2, 1},
		DstIP:    [4]byte{192, 0, 2, 2},
		SrcPort:  12345,
		DstPort:  27015,
	}

	// 60 queries should pass (60 PPS limit for Steam server browser)
	for i := 0; i < 60; i++ {
		res := gs.CheckGamePacket(pkt, a2sPayload)
		if res != FilterPass {
			t.Fatalf("Expected A2S query %d to pass, got %v", i, res)
		}
	}

	// 61st query should be dropped
	res := gs.CheckGamePacket(pkt, a2sPayload)
	if res != FilterDrop {
		t.Errorf("Expected 61st A2S query to be dropped, got %v", res)
	}
}

func TestGameShield_SAMPQueryLimiting(t *testing.T) {
	gs := NewGameShield(nil)

	// SAMP header: 'S','A','M','P' + IP (4) + Port (2) + 'i' (Info)
	sampPayload := []byte{'S', 'A', 'M', 'P', 127, 0, 0, 1, 0x1E, 0x61, 'i'}

	pkt := &packet.Packet{
		Protocol: packet.ProtoUDP,
		SrcIP:    [4]byte{192, 0, 2, 1},
		DstIP:    [4]byte{192, 0, 2, 2},
		SrcPort:  12345,
		DstPort:  7777,
	}

	// 30 queries should pass (30 PPS limit)
	for i := 0; i < 30; i++ {
		res := gs.CheckGamePacket(pkt, sampPayload)
		if res != FilterPass {
			t.Fatalf("Expected SAMP query %d to pass, got %v", i, res)
		}
	}

	// 31st query should be dropped
	res := gs.CheckGamePacket(pkt, sampPayload)
	if res != FilterDrop {
		t.Errorf("Expected 31st SAMP query to be dropped, got %v", res)
	}
}

func TestGameShield_QueryClassesDoNotPoisonSteamListingLimit(t *testing.T) {
	gs := NewGameShield(nil)
	pkt := &packet.Packet{
		Protocol: packet.ProtoUDP,
		SrcIP:    [4]byte{192, 0, 2, 50},
		DstIP:    [4]byte{192, 0, 2, 2},
		SrcPort:  12345,
		DstPort:  27015,
	}

	repeated := make([]byte, 32)
	for i := range repeated {
		repeated[i] = 0x41
	}
	for i := 0; i < 10; i++ {
		if got := gs.CheckGamePacket(pkt, repeated); got != FilterPass {
			t.Fatalf("repeated-payload packet %d dropped too early: %v", i+1, got)
		}
	}
	if got := gs.CheckGamePacket(pkt, repeated); got != FilterDrop {
		t.Fatalf("repeated-payload limiter was not enforced: %v", got)
	}

	// The same source must still receive its independent 60-PPS A2S budget.
	// Previously both signatures shared the first-created 10-PPS bucket, which
	// could make a healthy server disappear from the Steam browser.
	a2s := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x54, 'S', 'o', 'u', 'r', 'c', 'e'}
	for i := 0; i < 60; i++ {
		if got := gs.CheckGamePacket(pkt, a2s); got != FilterPass {
			t.Fatalf("A2S query %d inherited another protocol's limit: %v", i+1, got)
		}
	}
}

func TestGameShield_CustomPortRuleWithoutSignatureLimitsAllPayloads(t *testing.T) {
	gs := NewGameShield([]CustomGameRule{{Port: 9000, Protocol: "UDP", AllowPPS: 2}})
	pkt := &packet.Packet{
		Protocol: packet.ProtoUDP,
		SrcIP:    [4]byte{192, 0, 2, 10}, SrcPort: 50000, DstPort: 9000,
	}
	for i := 0; i < 2; i++ {
		if got := gs.CheckGamePacket(pkt, []byte("valid-game-payload")); got != FilterPass {
			t.Fatalf("custom rule dropped packet %d too early: %v", i, got)
		}
	}
	if got := gs.CheckGamePacket(pkt, []byte("valid-game-payload")); got != FilterDrop {
		t.Fatalf("custom rule did not enforce allow_pps: %v", got)
	}
}
