package engine

import (
	"testing"
	"time"

	"waf-game/pkg/packet"
	"waf-game/pkg/windivert"
)

func TestTCPShield_BasicTraffic(t *testing.T) {
	// TCP Shield with max 2 connections per IP, 10 rate, 10 subnet, 5s idle timeout
	ts := NewTCPShield(nil, 2, 10, 10, 5)

	synPkt := &packet.Packet{
		Version:  4,
		IHL:      5,
		TotalLen: 40,
		Protocol: packet.ProtoTCP,
		SrcIP:    [4]byte{192, 0, 2, 1},
		DstIP:    [4]byte{192, 0, 2, 2},
		SrcPort:  12345,
		DstPort:  80,
		TCPFlags: packet.TCPFlagSYN,
		SeqNum:   1000,
	}

	// 1. Process SYN - should return FilterPass
	var addr windivert.Address
	res := ts.ProcessTCP(synPkt, nil, &addr)
	if res != FilterPass {
		t.Errorf("Expected FilterPass for SYN packet, got %v", res)
	}

	if ts.GetVerifiedCount() != 1 {
		t.Errorf("Expected tracked count 1, got %d", ts.GetVerifiedCount())
	}

	// 2. Client sends ACK
	ackPkt := &packet.Packet{
		Version:  4,
		IHL:      5,
		TotalLen: 40,
		Protocol: packet.ProtoTCP,
		SrcIP:    [4]byte{192, 0, 2, 1},
		DstIP:    [4]byte{192, 0, 2, 2},
		SrcPort:  12345,
		DstPort:  80,
		TCPFlags: packet.TCPFlagACK,
		SeqNum:   1001,
		AckNum:   1001,
	}

	res = ts.ProcessTCP(ackPkt, nil, &addr)
	if res != FilterPass {
		t.Errorf("Expected FilterPass for valid ACK, got %v", res)
	}

	// 3. Subsequent packet (data/payload) should pass directly
	dataPkt := &packet.Packet{
		Version:    4,
		IHL:        5,
		TotalLen:   100,
		Protocol:   packet.ProtoTCP,
		SrcIP:      [4]byte{192, 0, 2, 1},
		DstIP:      [4]byte{192, 0, 2, 2},
		SrcPort:    12345,
		DstPort:    80,
		TCPFlags:   packet.TCPFlagACK,
		PayloadLen: 60,
	}

	res = ts.ProcessTCP(dataPkt, nil, &addr)
	if res != FilterPass {
		t.Errorf("Expected subsequent data packet to pass directly, got %v", res)
	}
}

func TestTCPShield_IPConnectionLimits(t *testing.T) {
	// Max 2 connections per IP
	ts := NewTCPShield(nil, 2, 10, 10, 5)
	var addr windivert.Address

	// Establish 2 connections
	conns := []uint16{10001, 10002}
	for _, port := range conns {
		syn := &packet.Packet{
			Version:  4,
			IHL:      5,
			TotalLen: 40,
			Protocol: packet.ProtoTCP,
			SrcIP:    [4]byte{192, 0, 2, 1},
			DstIP:    [4]byte{192, 0, 2, 2},
			SrcPort:  port,
			DstPort:  80,
			TCPFlags: packet.TCPFlagSYN,
		}
		res := ts.ProcessTCP(syn, nil, &addr)
		if res != FilterPass {
			t.Errorf("Expected pass for SYN, got %v", res)
		}
	}

	if ts.GetVerifiedCount() != 2 {
		t.Errorf("Expected 2 tracked connections, got %d", ts.GetVerifiedCount())
	}

	// Try third connection from same IP - should be dropped due to IP connection limits
	thirdSyn := &packet.Packet{
		Version:  4,
		IHL:      5,
		TotalLen: 40,
		Protocol: packet.ProtoTCP,
		SrcIP:    [4]byte{192, 0, 2, 1},
		DstIP:    [4]byte{192, 0, 2, 2},
		SrcPort:  10003,
		DstPort:  80,
		TCPFlags: packet.TCPFlagSYN,
	}

	res := ts.ProcessTCP(thirdSyn, nil, &addr)
	if res != FilterDrop {
		t.Errorf("Expected third SYN to be dropped due to IP connection limit, got %v", res)
	}
}

func TestTCPShield_SYNRateLimiting(t *testing.T) {
	ts := NewTCPShield(nil, 100, 50, 100, 5)
	ts.blacklistDur = 1 * time.Second
	var addr windivert.Address

	// IP 192.0.2.1 floods SYNs (limit is 15 PPS)
	for i := 0; i < 15; i++ {
		syn := &packet.Packet{
			Version:  4,
			IHL:      5,
			TotalLen: 40,
			Protocol: packet.ProtoTCP,
			SrcIP:    [4]byte{192, 0, 2, 1},
			DstIP:    [4]byte{192, 0, 2, 2},
			SrcPort:  uint16(20000 + i),
			DstPort:  80,
			TCPFlags: packet.TCPFlagSYN,
		}
		res := ts.ProcessTCP(syn, nil, &addr)
		if res != FilterPass {
			t.Fatalf("Expected SYN %d to pass, got %v", i, res)
		}
	}

	// 16th SYN within the same second should trigger blacklist and be dropped
	floodSyn := &packet.Packet{
		Version:  4,
		IHL:      5,
		TotalLen: 40,
		Protocol: packet.ProtoTCP,
		SrcIP:    [4]byte{192, 0, 2, 1},
		DstIP:    [4]byte{192, 0, 2, 2},
		SrcPort:  20016,
		DstPort:  80,
		TCPFlags: packet.TCPFlagSYN,
	}
	res := ts.ProcessTCP(floodSyn, nil, &addr)
	if res != FilterDrop {
		t.Errorf("Expected flooded SYN to be dropped, got %v", res)
	}

	// Wait for blacklist to expire
	time.Sleep(1100 * time.Millisecond)

	// Should pass again
	res = ts.ProcessTCP(floodSyn, nil, &addr)
	if res != FilterPass {
		t.Errorf("Expected SYN to pass after blacklist expired, got %v", res)
	}
}

func TestTCPShield_IdleReaper(t *testing.T) {
	ts := NewTCPShield(nil, 5, 10, 10, 1)
	var addr windivert.Address

	syn := &packet.Packet{
		Version:  4,
		IHL:      5,
		TotalLen: 40,
		Protocol: packet.ProtoTCP,
		SrcIP:    [4]byte{192, 0, 2, 1},
		DstIP:    [4]byte{192, 0, 2, 2},
		SrcPort:  12345,
		DstPort:  80,
		TCPFlags: packet.TCPFlagSYN,
	}
	ts.ProcessTCP(syn, nil, &addr)

	if ts.GetVerifiedCount() != 1 {
		t.Errorf("Expected 1 tracked connection")
	}

	time.Sleep(1100 * time.Millisecond)

	reaped := ts.ReapIdleConnections()
	if reaped != 1 {
		t.Errorf("Expected 1 connection reaped, got %d", reaped)
	}
	if ts.GetVerifiedCount() != 0 {
		t.Errorf("Expected 0 connections after reap, got %d", ts.GetVerifiedCount())
	}
}

func TestTCPShield_SYNCookie(t *testing.T) {
	ts := NewTCPShield(nil, 50, 10, 100, 5)

	srcIP := [4]byte{203, 0, 113, 50}
	dstIP := [4]byte{198, 51, 100, 1}
	srcPort := uint16(54321)
	dstPort := uint16(80)

	// 1. Generate valid cookie
	cookie := ts.GenerateSYNCookie(srcIP, dstIP, srcPort, dstPort)
	if cookie == 0 {
		t.Errorf("Expected non-zero cookie")
	}

	// 2. Validate cookie
	if !ts.ValidateSYNCookie(srcIP, dstIP, srcPort, dstPort, cookie) {
		t.Errorf("Expected cookie validation to succeed for valid parameters")
	}

	// 3. Spoofed IP / Port must fail validation
	if ts.ValidateSYNCookie(srcIP, dstIP, srcPort+1, dstPort, cookie) {
		t.Errorf("Expected cookie validation to fail for mismatched port")
	}

	spoofedIP := [4]byte{203, 0, 113, 51}
	if ts.ValidateSYNCookie(spoofedIP, dstIP, srcPort, dstPort, cookie) {
		t.Errorf("Expected cookie validation to fail for mismatched IP")
	}

	// 4. Test complete handshake flow with SYN Cookie via ProcessTCP
	var addr windivert.Address
	ackPkt := &packet.Packet{
		Version:  4,
		IHL:      5,
		TotalLen: 40,
		Protocol: packet.ProtoTCP,
		SrcIP:    srcIP,
		DstIP:    dstIP,
		SrcPort:  srcPort,
		DstPort:  dstPort,
		TCPFlags: packet.TCPFlagACK,
		AckNum:   cookie + 1, // Client ACKs the SYN cookie ISN
	}

	// Process ACK with cookie — should automatically verify and pass
	res := ts.ProcessTCP(ackPkt, nil, &addr)
	if res != FilterPass {
		t.Errorf("Expected ACK with valid SYN cookie to pass, got %v", res)
	}

	if ts.GetVerifiedCount() != 1 {
		t.Errorf("Expected 1 verified connection after SYN cookie ACK")
	}
}

func TestTCPShield_SlowlorisReaper(t *testing.T) {
	ts := NewTCPShield(nil, 50, 10, 100, 5)
	var addr windivert.Address

	syn := &packet.Packet{
		Version:  4,
		IHL:      5,
		TotalLen: 40,
		Protocol: packet.ProtoTCP,
		SrcIP:    [4]byte{192, 0, 2, 99},
		DstIP:    [4]byte{192, 0, 2, 2},
		SrcPort:  33333,
		DstPort:  80,
		TCPFlags: packet.TCPFlagSYN,
	}
	ts.ProcessTCP(syn, nil, &addr)

	ack := &packet.Packet{
		Version:  4,
		IHL:      5,
		TotalLen: 40,
		Protocol: packet.ProtoTCP,
		SrcIP:    [4]byte{192, 0, 2, 99},
		DstIP:    [4]byte{192, 0, 2, 2},
		SrcPort:  33333,
		DstPort:  80,
		TCPFlags: packet.TCPFlagACK,
	}
	ts.ProcessTCP(ack, nil, &addr)

	// Simulate slow connection by artificially setting HandshakeAt to 20 seconds ago
	connKey := syn.ConnKey()
	if entry, ok := ts.verified.Get(connKey); ok {
		entry.Value.HandshakeAt = time.Now().UnixNano() - int64(20*time.Second)
		entry.Value.BytesTransferred = 10 // Less than 64 bytes in 20 seconds (Slowloris pattern)
	}

	reaped := ts.ReapSlowlorisConnections()
	if reaped != 1 {
		t.Errorf("Expected 1 Slowloris connection to be reaped, got %d", reaped)
	}
	if ts.GetVerifiedCount() != 0 {
		t.Errorf("Expected 0 connections remaining, got %d", ts.GetVerifiedCount())
	}
}


