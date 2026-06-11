package engine

import (
	"testing"
	"time"

	"waf-game/pkg/packet"
	"waf-game/pkg/windivert"
)

func TestTCPShield_BasicTraffic(t *testing.T) {
	// TCP Shield with max 2 connections per IP, 5s idle timeout
	ts := NewTCPShield(nil, 2, 5)

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

	// 1. Process SYN - should return FilterPass (transparent allow)
	var addr windivert.Address
	res := ts.ProcessTCP(synPkt, nil, &addr)
	if res != FilterPass {
		t.Errorf("Expected FilterPass for SYN packet, got %v", res)
	}

	// Verify connection is now tracked
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
	ts := NewTCPShield(nil, 2, 5)
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
	// Large connection limit, 1 second blacklist duration
	ts := NewTCPShield(nil, 100, 5)
	ts.blacklistDur = 1 * time.Second
	var addr windivert.Address

	// IP 192.0.2.1 floods SYNs (limit is 10 PPS)
	for i := 0; i < 10; i++ {
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

	// 11th SYN within the same second should trigger blacklist and be dropped
	floodSyn := &packet.Packet{
		Version:  4,
		IHL:      5,
		TotalLen: 40,
		Protocol: packet.ProtoTCP,
		SrcIP:    [4]byte{192, 0, 2, 1},
		DstIP:    [4]byte{192, 0, 2, 2},
		SrcPort:  20011,
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
	// 1 second idle timeout
	ts := NewTCPShield(nil, 5, 1)
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

	// Wait for connection to exceed 1 second idle time
	time.Sleep(1100 * time.Millisecond)

	reaped := ts.ReapIdleConnections()
	if reaped != 1 {
		t.Errorf("Expected 1 connection reaped, got %d", reaped)
	}
	if ts.GetVerifiedCount() != 0 {
		t.Errorf("Expected 0 connections after reap, got %d", ts.GetVerifiedCount())
	}
}
