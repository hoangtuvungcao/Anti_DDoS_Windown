package engine

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"waf-game/pkg/datastore"
	"waf-game/pkg/packet"
	"waf-game/pkg/windivert"
)

func TestTCPShield_ConcurrentConnectionLimitIsAtomic(t *testing.T) {
	ts := NewTCPShield(nil, 10, 1_000, 1_000, 90)
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(port uint16) {
			defer wg.Done()
			pkt := &packet.Packet{
				Version: 4, IHL: 5, TotalLen: 40, Protocol: packet.ProtoTCP,
				SrcIP: [4]byte{192, 0, 2, 90}, DstIP: [4]byte{192, 0, 2, 2},
				SrcPort: port, DstPort: 27015, TCPFlags: packet.TCPFlagSYN,
			}
			ts.ProcessTCP(pkt, nil, &windivert.Address{})
		}(uint16(30000 + i))
	}
	wg.Wait()

	if got := ts.GetVerifiedCount(); got != 10 {
		t.Fatalf("concurrent max-connection limit admitted %d flows, want 10", got)
	}
	entry, ok := ts.connPerIP.Get(uint64(0xc000025a))
	if !ok || entry.Value.Load() != 10 {
		t.Fatalf("atomic IP counter mismatch: found=%v value=%v", ok, func() int32 {
			if !ok {
				return -1
			}
			return entry.Value.Load()
		}())
	}
}

func TestTCPShield_ConcurrentDuplicateSYNCountsOnce(t *testing.T) {
	ts := NewTCPShield(nil, 100, 1_000, 1_000, 90)
	pkt := &packet.Packet{
		Version: 4, IHL: 5, TotalLen: 40, Protocol: packet.ProtoTCP,
		SrcIP: [4]byte{192, 0, 2, 92}, DstIP: [4]byte{192, 0, 2, 2},
		SrcPort: 32000, DstPort: 27015, TCPFlags: packet.TCPFlagSYN,
	}
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ts.ProcessTCP(pkt, nil, &windivert.Address{})
		}()
	}
	wg.Wait()
	entry, ok := ts.connPerIP.Get(pkt.IPFlowKey())
	if !ok || entry.Value.Load() != 1 || ts.GetVerifiedCount() != 1 {
		t.Fatalf("duplicate SYN accounting mismatch: found=%v counter=%v flows=%d", ok, func() int32 {
			if !ok {
				return -1
			}
			return entry.Value.Load()
		}(), ts.GetVerifiedCount())
	}
}

func TestTCPShield_OutboundFlowDoesNotDecrementInboundCounter(t *testing.T) {
	ts := NewTCPShield(nil, 100, 1_000, 1_000, 90)
	clientIP := [4]byte{198, 51, 100, 93}
	inbound := &packet.Packet{
		Version: 4, IHL: 5, TotalLen: 40, Protocol: packet.ProtoTCP,
		SrcIP: clientIP, DstIP: [4]byte{192, 0, 2, 2},
		SrcPort: 33000, DstPort: 27015, TCPFlags: packet.TCPFlagSYN,
	}
	ts.ProcessTCP(inbound, nil, &windivert.Address{})
	ts.TrackOutbound(clientIP, 443, 51000)
	outboundReplyFIN := &packet.Packet{
		Version: 4, IHL: 5, TotalLen: 40, Protocol: packet.ProtoTCP,
		SrcIP: clientIP, DstIP: [4]byte{192, 0, 2, 2},
		SrcPort: 443, DstPort: 51000, TCPFlags: packet.TCPFlagFIN | packet.TCPFlagACK,
	}
	ts.ProcessTCP(outboundReplyFIN, nil, &windivert.Address{})
	entry, ok := ts.connPerIP.Get(inbound.IPFlowKey())
	if !ok || entry.Value.Load() != 1 {
		t.Fatalf("outbound flow corrupted inbound connection count: found=%v", ok)
	}
}

func TestTCPShield_UnsolicitedSYNACKIsNotTrusted(t *testing.T) {
	ts := NewTCPShield(nil, 100, 100, 500, 90)
	ts.SetStrict(true)
	pkt := &packet.Packet{
		Version: 4, IHL: 5, TotalLen: 40, Protocol: packet.ProtoTCP,
		SrcIP: [4]byte{198, 51, 100, 91}, DstIP: [4]byte{192, 0, 2, 2},
		SrcPort: 443, DstPort: 51000,
		TCPFlags: packet.TCPFlagSYN | packet.TCPFlagACK,
	}

	if got := ts.ProcessTCP(pkt, nil, &windivert.Address{}); got != FilterPass {
		t.Fatalf("first SYN-ACK should reach the Windows TCP stack: %v", got)
	}
	if ts.IsVerified(pkt.ConnKey()) {
		t.Fatal("unsolicited SYN-ACK was promoted to a trusted connection")
	}
	for i := 1; i < 30; i++ {
		if got := ts.ProcessTCP(pkt, nil, &windivert.Address{}); got != FilterPass {
			t.Fatalf("SYN-ACK rate limiter dropped packet %d too early: %v", i+1, got)
		}
	}
	if got := ts.ProcessTCP(pkt, nil, &windivert.Address{}); got != FilterDrop {
		t.Fatalf("SYN-ACK flood was not rate-limited: %v", got)
	}
}

func TestTCPShield_KernelEstablishedConnectionSurvivesStrictMode(t *testing.T) {
	ts := NewTCPShield(nil, 150, 60, 500, 1)
	rdp := &packet.Packet{
		Version:    4,
		IHL:        5,
		TotalLen:   80,
		Protocol:   packet.ProtoTCP,
		SrcIP:      [4]byte{203, 0, 113, 25},
		DstIP:      [4]byte{192, 0, 2, 2},
		SrcPort:    53000,
		DstPort:    45678, // Deliberately non-standard: no port-based trust.
		TCPFlags:   packet.TCPFlagACK | packet.TCPFlagPSH,
		PayloadLen: 40,
	}

	// Simulate any connection that Windows confirms was already established.
	ts.ObserveTCP(rdp, true)
	entry, ok := ts.verified.Get(rdp.ConnKey())
	if !ok {
		t.Fatal("monitoring must learn a kernel-established connection")
	}
	atomic.StoreInt64(&entry.LastSeen, time.Now().Add(-5*time.Second).UnixNano())
	if removed := ts.ReapIdleConnections(); removed != 1 {
		t.Fatalf("idle sweep did not clean stale state: removed=%d", removed)
	}
	// The engine consults Windows before filtering and safely re-adopts it.
	ts.ObserveTCP(rdp, true)

	// A dynamic SYN-flood blacklist must affect new traffic, not tear down the
	// already verified administrator session.
	ipKey := rdp.IPFlowKey()
	bucket, _ := ts.synBuckets.GetOrCreate(ipKey, func() *datastore.IPBucket {
		return datastore.NewIPBucket(1)
	})
	bucket.Value.Blacklist(time.Minute)
	ts.SetStrict(true)
	if got := ts.ProcessTCP(rdp, nil, &windivert.Address{}); got != FilterPass {
		t.Fatalf("verified connection was dropped in strict mode: %v", got)
	}

	newRDP := *rdp
	newRDP.SrcPort++
	newRDP.TCPFlags = packet.TCPFlagSYN
	newRDP.PayloadLen = 0
	if got := ts.ProcessTCP(&newRDP, nil, &windivert.Address{}); got != FilterDrop {
		t.Fatalf("new SYN from blacklisted attacker must still be dropped: %v", got)
	}
}

func TestTCPShield_MonitorDoesNotTrustUnsolicitedACKFlood(t *testing.T) {
	ts := NewTCPShield(nil, 150, 60, 500, 90)
	ack := &packet.Packet{
		Version:  4,
		IHL:      5,
		TotalLen: 40,
		Protocol: packet.ProtoTCP,
		SrcIP:    [4]byte{198, 51, 100, 99},
		DstIP:    [4]byte{192, 0, 2, 2},
		SrcPort:  54000,
		DstPort:  7777,
		TCPFlags: packet.TCPFlagACK,
	}
	ts.ObserveTCP(ack, false)
	if ts.IsVerified(ack.ConnKey()) {
		t.Fatal("monitoring trusted an unsolicited non-management ACK")
	}
	ts.SetStrict(true)
	if got := ts.ProcessTCP(ack, nil, &windivert.Address{}); got != FilterDrop {
		t.Fatalf("strict mode must drop an unsolicited ACK flood: %v", got)
	}
}

func TestTCPShield_HalfOpenStillExpires(t *testing.T) {
	ts := NewTCPShield(nil, 150, 60, 500, 90)
	syn := &packet.Packet{
		Version: 4, IHL: 5, TotalLen: 40, Protocol: packet.ProtoTCP,
		SrcIP: [4]byte{198, 51, 100, 10}, DstIP: [4]byte{192, 0, 2, 2},
		SrcPort: 55000, DstPort: 45678, TCPFlags: packet.TCPFlagSYN,
	}
	ts.ObserveTCP(syn, false)
	entry, ok := ts.verified.Get(syn.ConnKey())
	if !ok {
		t.Fatal("expected SYN to be tracked")
	}
	state := entry.Value
	state.VerifiedAt = time.Now().Add(-time.Minute).UnixNano()
	ts.verified.Set(syn.ConnKey(), state)
	if removed := ts.ReapHalfOpenAndZeroPayload(); removed != 1 {
		t.Fatalf("SYN flood entry was retained: removed=%d", removed)
	}
}

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
	// connRateLimitIP=15 → SYN bucket allows 15 PPS; 16th should be dropped
	ts := NewTCPShield(nil, 100, 15, 100, 5)
	ts.blacklistDur = 1 * time.Second
	var addr windivert.Address

	// IP 192.0.2.1 floods SYNs (limit is 15 PPS via connRateLimitIP)
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

	// Simulate slow connection by artificially setting HandshakeAt to 200 seconds ago
	connKey := syn.ConnKey()
	if entry, ok := ts.verified.Get(connKey); ok {
		entry.Value.HandshakeAt = time.Now().UnixNano() - int64(200*time.Second)
		entry.Value.BytesTransferred = 10 // Less than 64 bytes in 200 seconds (Slowloris pattern)
	}

	reaped := ts.ReapSlowlorisConnections()
	if reaped != 1 {
		t.Errorf("Expected 1 Slowloris connection to be reaped, got %d", reaped)
	}
	if ts.GetVerifiedCount() != 0 {
		t.Errorf("Expected 0 connections remaining, got %d", ts.GetVerifiedCount())
	}
}
