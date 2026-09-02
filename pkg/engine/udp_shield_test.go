package engine

import (
	"testing"
	"time"

	"waf-game/pkg/packet"
)

func TestUDPShield_RateLimiting(t *testing.T) {
	// 10 PPS per-flow, 1000 BPS per-flow, 20 PPS per-IP, 50 PPS per-Subnet
	us := NewUDPShield(10, 1000, 20, 50, 5*time.Second, nil)

	pkt := &packet.Packet{
		Version:       4,
		IHL:           5,
		TotalLen:      50,
		Protocol:      packet.ProtoUDP,
		SrcIP:         [4]byte{192, 0, 2, 1},
		DstIP:         [4]byte{192, 0, 2, 2},
		SrcPort:       10001,
		DstPort:       27015,
		PayloadLen:    22,
		PayloadOffset: 28,
	}

	// 1. Packet should pass initially
	res := us.ProcessUDP(pkt, make([]byte, 50))
	if res != FilterPass {
		t.Errorf("Expected initial UDP packet to pass, got %v", res)
	}

	// 2. Consume per-flow PPS limit (10 PPS)
	for i := 0; i < 9; i++ {
		us.ProcessUDP(pkt, make([]byte, 50))
	}

	// 11th packet for flow should be blocked and trigger blacklist
	res = us.ProcessUDP(pkt, make([]byte, 50))
	if res != FilterDrop {
		t.Errorf("Expected packet to be drop due to flow rate limits, got %v", res)
	}

	// 3. New flow from same IP should be blocked if we exceed aggregate IP limit (5 PPS)
	us2 := NewUDPShield(100, 10000, 5, 50, 5*time.Second, nil) // IP limit = 5 PPS
	pktA := &packet.Packet{
		Version:    4,
		IHL:        5,
		TotalLen:   50,
		Protocol:   packet.ProtoUDP,
		SrcIP:      [4]byte{192, 0, 2, 1},
		DstIP:      [4]byte{192, 0, 2, 2},
		SrcPort:    10001,
		DstPort:    27015,
		PayloadLen: 22,
	}
	pktB := &packet.Packet{
		Version:    4,
		IHL:        5,
		TotalLen:   50,
		Protocol:   packet.ProtoUDP,
		SrcIP:      [4]byte{192, 0, 2, 1},
		DstIP:      [4]byte{192, 0, 2, 2},
		SrcPort:    10002, // Different source port (different flow, same IP)
		DstPort:    27015,
		PayloadLen: 22,
	}

	// Send 3 to flow A, 2 to flow B (total 5 from IP)
	for i := 0; i < 3; i++ {
		us2.ProcessUDP(pktA, make([]byte, 50))
	}
	for i := 0; i < 2; i++ {
		us2.ProcessUDP(pktB, make([]byte, 50))
	}

	// 6th packet from the same IP (flow B) should trigger IP blacklist and drop
	res = us2.ProcessUDP(pktB, make([]byte, 50))
	if res != FilterDrop {
		t.Errorf("Expected packet to be dropped due to IP rate limits, got %v", res)
	}
}

func TestUDPShield_SubnetLimiting(t *testing.T) {
	// High per-flow and per-IP limit, but 10 PPS Subnet limit (simulating botnet across /24 subnet)
	us := NewUDPShield(100, 10000, 50, 10, 5*time.Second, nil)

	// Send 10 packets from 10 DIFFERENT IPs in the same subnet (192.0.2.1 .. 192.0.2.10)
	for i := 1; i <= 10; i++ {
		pkt := &packet.Packet{
			Version:    4,
			IHL:        5,
			TotalLen:   50,
			Protocol:   packet.ProtoUDP,
			SrcIP:      [4]byte{192, 0, 2, byte(i)},
			DstIP:      [4]byte{192, 0, 2, 254},
			SrcPort:    uint16(30000 + i),
			DstPort:    27015,
			PayloadLen: 22,
		}
		res := us.ProcessUDP(pkt, make([]byte, 50))
		if res != FilterPass {
			t.Fatalf("Expected packet from IP %d to pass, got %v", i, res)
		}
	}

	// 11th packet from an 11th IP in the same /24 subnet should be blocked by Subnet rate limiter
	pkt11 := &packet.Packet{
		Version:    4,
		IHL:        5,
		TotalLen:   50,
		Protocol:   packet.ProtoUDP,
		SrcIP:      [4]byte{192, 0, 2, 11},
		DstIP:      [4]byte{192, 0, 2, 254},
		SrcPort:    30011,
		DstPort:    27015,
		PayloadLen: 22,
	}

	res := us.ProcessUDP(pkt11, make([]byte, 50))
	if res != FilterDrop {
		t.Errorf("Expected 11th packet from subnet to be dropped by Subnet rate limiter, got %v", res)
	}
}

func TestUDPShieldReportsDropReasonAndBlacklistsRepeatOffender(t *testing.T) {
	us := NewUDPShield(2, 10000, 100, 100, time.Minute, nil)
	pkt := &packet.Packet{Version: 4, IHL: 5, TotalLen: 40, Protocol: packet.ProtoUDP, SrcIP: [4]byte{203, 0, 113, 9}, SrcPort: 5000, DstPort: 27015}
	us.ProcessUDP(pkt, make([]byte, 40))
	us.ProcessUDP(pkt, make([]byte, 40))
	for i := 0; i < 8; i++ {
		result, reason := us.ProcessUDPWithReason(pkt, make([]byte, 40))
		if result != FilterDrop || (reason != DropFlowRate && reason != DropBlacklisted) {
			t.Fatalf("unexpected mitigation decision: result=%v reason=%v", result, reason)
		}
	}
	if us.GetBlacklistedCount() == 0 {
		t.Fatal("repeat UDP offender was not blacklisted")
	}
}

func TestUDPShield_Entropy(t *testing.T) {
	us := NewUDPShield(100, 10000, 200, 500, 5*time.Second, nil)
	us.SetEntropy(true)

	// Low entropy: repeated zeros
	lowEntropyPayload := make([]byte, 100) // All zeros
	pktLow := &packet.Packet{
		Version:       4,
		IHL:           5,
		TotalLen:      128,
		Protocol:      packet.ProtoUDP,
		SrcIP:         [4]byte{192, 0, 2, 1},
		DstIP:         [4]byte{192, 0, 2, 2},
		SrcPort:       12345,
		DstPort:       27015,
		PayloadOffset: 28,
		PayloadLen:    100,
	}

	res := us.ProcessUDP(pktLow, pktLowBytes(lowEntropyPayload))
	if res != FilterDrop {
		t.Errorf("Expected low-entropy packet to be dropped, got %v", res)
	}

	// High entropy: permutation of all 256 possible byte values (entropy = exactly 8.0)
	highEntropyPayload := make([]byte, 256)
	for i := 0; i < 256; i++ {
		highEntropyPayload[i] = byte(i)
	}
	pktHigh := &packet.Packet{
		Version:       4,
		IHL:           5,
		TotalLen:      284,
		Protocol:      packet.ProtoUDP,
		SrcIP:         [4]byte{192, 0, 2, 1},
		DstIP:         [4]byte{192, 0, 2, 2},
		SrcPort:       12346,
		DstPort:       27015,
		PayloadOffset: 28,
		PayloadLen:    256,
	}

	res = us.ProcessUDP(pktHigh, pktLowBytes(highEntropyPayload))
	if res != FilterDrop {
		t.Errorf("Expected high-entropy packet to be dropped, got %v", res)
	}

	// Normal entropy: english text
	normalPayload := []byte("This is a normal game message with structuring, standard printable text.")
	pktNormal := &packet.Packet{
		Version:       4,
		IHL:           5,
		TotalLen:      uint16(28 + len(normalPayload)),
		Protocol:      packet.ProtoUDP,
		SrcIP:         [4]byte{192, 0, 2, 1},
		DstIP:         [4]byte{192, 0, 2, 2},
		SrcPort:       12347,
		DstPort:       27015,
		PayloadOffset: 28,
		PayloadLen:    len(normalPayload),
	}

	res = us.ProcessUDP(pktNormal, pktLowBytes(normalPayload))
	if res != FilterPass {
		t.Errorf("Expected normal-entropy packet to pass, got %v", res)
	}
}

func pktLowBytes(payload []byte) []byte {
	buf := make([]byte, 28+len(payload))
	copy(buf[28:], payload)
	return buf
}
