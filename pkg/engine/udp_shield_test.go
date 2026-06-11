package engine

import (
	"testing"
	"time"

	"waf-game/pkg/packet"
)

func TestUDPShield_RateLimiting(t *testing.T) {
	// 10 PPS per-flow, 1000 BPS per-flow, 20 PPS per-IP
	us := NewUDPShield(10, 1000, 20, 5*time.Second)

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

	// 3. New flow from same IP should be blocked if we exceed aggregate IP limit (20 PPS)
	us2 := NewUDPShield(100, 10000, 5, 5*time.Second) // IP limit = 5 PPS
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

func TestUDPShield_Entropy(t *testing.T) {
	us := NewUDPShield(100, 10000, 200, 5*time.Second)
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

func TestUDPShield_TwoWayVerify(t *testing.T) {
	us := NewUDPShield(100, 10000, 200, 5*time.Second)
	us.SetTwoWay(true)

	pkt := &packet.Packet{
		Version:    4,
		IHL:        5,
		TotalLen:   50,
		Protocol:   packet.ProtoUDP,
		SrcIP:      [4]byte{192, 0, 2, 1},
		DstIP:      [4]byte{192, 0, 2, 2},
		SrcPort:    12345,
		DstPort:    27015,
		PayloadLen: 22,
	}

	// 1. Without outbound response, packet should be dropped (not verified client)
	res := us.ProcessUDP(pkt, make([]byte, 50))
	if res != FilterDrop {
		t.Errorf("Expected packet to be dropped without outbound tracking, got %v", res)
	}

	// 2. Track outbound response to the client
	us.TrackOutbound(pkt.SrcIP, pkt.SrcPort)

	// 3. Packet should now pass
	res = us.ProcessUDP(pkt, make([]byte, 50))
	if res != FilterPass {
		t.Errorf("Expected packet to pass after outbound response tracked, got %v", res)
	}
}

func pktLowBytes(payload []byte) []byte {
	buf := make([]byte, 28+len(payload))
	copy(buf[28:], payload)
	return buf
}
