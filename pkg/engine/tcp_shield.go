package engine

import (
	"encoding/binary"
	"fmt"
	"sync"
	"time"

	"waf-game/pkg/datastore"
	"waf-game/pkg/packet"
	"waf-game/pkg/windivert"
)

// TCPShield implements Layer 3: TCP SYN Rate Limiting + Connection Limiter + Idle Reaper.
// Protects ALL TCP ports automatically detected by Layer 2.
type TCPShield struct {
	mu sync.RWMutex

	// Tracked connections
	// Key = ConnKey (srcIP + srcPort + dstPort)
	verified *datastore.ShardedMap[TCPConnState]

	// Per-IP connection counter
	connPerIP *datastore.ShardedMap[int32]

	// Per-IP SYN rate limiters
	synBuckets *datastore.ShardedMap[datastore.IPBucket]

	// Verified client IPs (passed SYN cookie check)
	verifiedClients *datastore.ShardedMap[int64]

	// Out-of-state rate limiters per IP to detect botnets (ACK/FIN/RST floods)
	outOfStateBuckets *datastore.ShardedMap[datastore.IPBucket]

	// Settings
	maxConnPerIP   int32
	idleTimeoutSec int64
	enabled        bool
	strict         bool
	secret         uint32
	blacklistDur   time.Duration

	// WinDivert handle (used for sending packets)
	handle *windivert.Handle
}

// TCPConnState tracks state of a tracked TCP connection
type TCPConnState struct {
	VerifiedAt   int64 // When connection was first seen
	LastActivity int64 // Last packet seen
	HasPayload   bool  // Whether any data was sent after handshake
}

// NewTCPShield creates a new TCP Shield module.
func NewTCPShield(handle *windivert.Handle, maxConnPerIP int32, idleTimeoutSec int64) *TCPShield {
	randSecret := uint32(time.Now().UnixNano())
	return &TCPShield{
		verified:          datastore.NewShardedMap[TCPConnState](100000),
		connPerIP:         datastore.NewShardedMap[int32](50000),
		synBuckets:        datastore.NewShardedMap[datastore.IPBucket](50000),
		verifiedClients:   datastore.NewShardedMap[int64](100000),
		outOfStateBuckets: datastore.NewShardedMap[datastore.IPBucket](50000),
		maxConnPerIP:      maxConnPerIP,
		idleTimeoutSec:    idleTimeoutSec,
		enabled:           true,
		strict:            false,
		secret:            randSecret,
		blacklistDur:      5 * time.Minute,
		handle:            handle,
	}
}

// TrackOutbound registers an outbound TCP connection from the server.
func (ts *TCPShield) TrackOutbound(dstIP [4]byte, dstPort, srcPort uint16) {
	ipVal := binary.BigEndian.Uint32(dstIP[:])
	connKey := uint64(ipVal)<<32 | uint64(dstPort)<<16 | uint64(srcPort)
	now := time.Now().UnixNano()
	ts.verified.Set(connKey, TCPConnState{
		VerifiedAt:   now,
		LastActivity: now,
		HasPayload:   false,
	})
}

// SetStrict enables or disables strict stateful filtering (War Mode).
func (ts *TCPShield) SetStrict(val bool) {
	ts.strict = val
}

// ProcessTCP handles a TCP packet through rate limiting and tracking.
// Returns FilterPass to allow, FilterDrop to block.
func (ts *TCPShield) ProcessTCP(pkt *packet.Packet, rawBuf []byte, addr *windivert.Address) FilterResult {
	if !ts.enabled {
		return FilterPass
	}

	connKey := pkt.ConnKey()
	ipKey := pkt.IPFlowKey()

	// 1. RST/FIN packets — cleanup and allow through
	if pkt.IsRST() || pkt.IsFIN() {
		if _, ok := ts.verified.Get(connKey); ok {
			ts.verified.Delete(connKey)
			if entry, ok := ts.connPerIP.Get(ipKey); ok {
				if entry.Value > 0 {
					entry.Value--
				}
			}
		}
		return FilterPass
	}

	// 2. Check if IP is blacklisted by SYN rate limiting
	if entry, ok := ts.synBuckets.Get(ipKey); ok {
		if entry.Value.IsBlacklisted() {
			return FilterDrop
		}
	}

	// 3. SYN packet — check limits and track
	if pkt.IsSYN() {
		// In strict mode (War Mode), perform SYN Cookie IP validation.
		if ts.strict {
			if _, ok := ts.verifiedClients.Get(ipKey); !ok {
				// IP not verified yet — send SYN-ACK cookie response
				ts.sendSYNACK(pkt, rawBuf, addr)
				return FilterDrop // Drop original SYN
			}
		}

		// Check per-IP connection limit
		connEntry, _ := ts.connPerIP.GetOrCreate(ipKey, func() int32 { return 0 })
		if connEntry.Value >= ts.maxConnPerIP {
			return FilterDrop // Too many connections
		}

		// Check SYN rate limit (max 10 SYNs per second per IP)
		synEntry, _ := ts.synBuckets.GetOrCreate(ipKey, func() datastore.IPBucket {
			return datastore.NewIPBucket(10) // 10 PPS limit
		})
		if !synEntry.Value.Allow() {
			synEntry.Value.Blacklist(ts.blacklistDur)
			return FilterDrop
		}

		// Register connection (starts as half-open)
		now := time.Now().UnixNano()
		ts.verified.Set(connKey, TCPConnState{
			VerifiedAt:   now,
			LastActivity: now,
			HasPayload:   false,
		})
		connEntry.Value++

		return FilterPass
	}

	// 4. For ACK or data packets:
	if entry, ok := ts.verified.Get(connKey); ok {
		state := &entry.Value
		now := time.Now().UnixNano()
		state.LastActivity = now
		entry.LastSeen = now

		if pkt.PayloadLen > 0 {
			state.HasPayload = true
		}
		return FilterPass
	}

	// Check if this is an ACK reply to our SYN Cookie challenge
	if ts.strict && pkt.IsACK() && (pkt.TCPFlags&packet.TCPFlagSYN == 0) {
		expectedCookie := ts.generateCookie(pkt.DstIP, pkt.SrcIP, pkt.DstPort, pkt.SrcPort)
		if pkt.AckNum == expectedCookie+1 {
			// IP verified! Add to verifiedClients cache
			now := time.Now().UnixNano()
			ts.verifiedClients.Set(ipKey, now)

			// Send RST to reset the verification handshake (client will reconnect instantly)
			ts.sendRST(pkt, rawBuf, addr)
			return FilterDrop
		}
	}

	// In strict mode (War Mode), check if IP is blacklisted for out-of-state packet flooding.
	if ts.strict {
		if entry, ok := ts.outOfStateBuckets.Get(ipKey); ok {
			if entry.Value.IsBlacklisted() {
				return FilterDrop
			}
		}

		// Rate limit out-of-state packets to 20 PPS per IP.
		// If exceeded, identify as botnet and blacklist the IP.
		bucketEntry, _ := ts.outOfStateBuckets.GetOrCreate(ipKey, func() datastore.IPBucket {
			return datastore.NewIPBucket(20) // 20 packets/sec threshold
		})
		if !bucketEntry.Value.Allow() {
			bucketEntry.Value.Blacklist(ts.blacklistDur)
			return FilterDrop
		}
	}

	// If we see packets for a connection we don't know in Peace Mode, allow it
	return FilterPass
}

// sendSYNACK sends a SYN-ACK cookie packet back to the client.
func (ts *TCPShield) sendSYNACK(pkt *packet.Packet, rawBuf []byte, addr *windivert.Address) {
	// Swap IPs in-place
	for i := 0; i < 4; i++ {
		rawBuf[12+i], rawBuf[16+i] = rawBuf[16+i], rawBuf[12+i]
	}

	// Swap ports
	tcpOffset := pkt.IPHeaderLen
	rawBuf[tcpOffset], rawBuf[tcpOffset+2] = rawBuf[tcpOffset+2], rawBuf[tcpOffset]
	rawBuf[tcpOffset+1], rawBuf[tcpOffset+3] = rawBuf[tcpOffset+3], rawBuf[tcpOffset+1]

	// Set Ack Number = Client Seq + 1
	ackNum := pkt.SeqNum + 1
	binary.BigEndian.PutUint32(rawBuf[tcpOffset+8:tcpOffset+12], ackNum)

	// Set Seq Number = Cookie
	cookie := ts.generateCookie(pkt.SrcIP, pkt.DstIP, pkt.SrcPort, pkt.DstPort)
	binary.BigEndian.PutUint32(rawBuf[tcpOffset+4:tcpOffset+8], cookie)

	// Set flags to SYN | ACK (SYN=0x02, ACK=0x10)
	rawBuf[tcpOffset+13] = packet.TCPFlagSYN | packet.TCPFlagACK

	// Recalculate checksums using WinDivert helper
	addr.SetOutbound(true)
	_ = ts.handle.CalcChecksums(rawBuf, addr, 0)

	// Send outbound
	_, _ = ts.handle.Send(rawBuf, addr)
}

// sendRST sends a RST packet to abort the validation connection.
func (ts *TCPShield) sendRST(pkt *packet.Packet, rawBuf []byte, addr *windivert.Address) {
	// Swap IPs
	for i := 0; i < 4; i++ {
		rawBuf[12+i], rawBuf[16+i] = rawBuf[16+i], rawBuf[12+i]
	}

	// Swap ports
	tcpOffset := pkt.IPHeaderLen
	rawBuf[tcpOffset], rawBuf[tcpOffset+2] = rawBuf[tcpOffset+2], rawBuf[tcpOffset]
	rawBuf[tcpOffset+1], rawBuf[tcpOffset+3] = rawBuf[tcpOffset+3], rawBuf[tcpOffset+1]

	// Set Seq Number = Client's Ack Number
	seq := pkt.AckNum
	binary.BigEndian.PutUint32(rawBuf[tcpOffset+4:tcpOffset+8], seq)

	// Set Ack Number = 0
	binary.BigEndian.PutUint32(rawBuf[tcpOffset+8:tcpOffset+12], 0)

	// Set flag to RST (RST=0x04, clear ACK)
	rawBuf[tcpOffset+13] = packet.TCPFlagRST

	// Recalculate checksums
	addr.SetOutbound(true)
	_ = ts.handle.CalcChecksums(rawBuf, addr, 0)

	// Send outbound
	_, _ = ts.handle.Send(rawBuf, addr)
}

// generateCookie generates a cryptographic-like cookie based on connection parameters and secret.
func (ts *TCPShield) generateCookie(srcIP, dstIP [4]byte, srcPort, dstPort uint16) uint32 {
	h := uint32(2166136261)
	for _, b := range srcIP {
		h = (h ^ uint32(b)) * 16777619
	}
	for _, b := range dstIP {
		h = (h ^ uint32(b)) * 16777619
	}
	h = (h ^ uint32(srcPort>>8)) * 16777619
	h = (h ^ uint32(srcPort&0xFF)) * 16777619
	h = (h ^ uint32(dstPort>>8)) * 16777619
	h = (h ^ uint32(dstPort&0xFF)) * 16777619
	h = (h ^ ts.secret) * 16777619
	return h
}

// ReapIdleConnections removes TCP connections that have been idle too long.
// Should be called periodically (every 3-5 seconds).
func (ts *TCPShield) ReapIdleConnections() int64 {
	idleCutoff := time.Duration(ts.idleTimeoutSec) * time.Second
	now := time.Now().UnixNano()

	// Sweep verified clients cache (expires after 5 minutes)
	ts.verifiedClients.Sweep(5 * time.Minute)

	// Sweep out-of-state rate limiters
	ts.outOfStateBuckets.Sweep(5 * time.Minute)

	return ts.verified.SweepWithCallback(idleCutoff, func(key uint64, state TCPConnState) {
		// Decrement per-IP counter
		// Extract IP from connKey (upper 32 bits)
		ipKey := key >> 32
		if entry, ok := ts.connPerIP.Get(ipKey); ok {
			if entry.Value > 0 {
				entry.Value--
			}
		}
		_ = state
		_ = now
	})
}

// GetVerifiedCount returns the number of tracked TCP connections.
func (ts *TCPShield) GetVerifiedCount() int64 {
	return ts.verified.Count()
}

// GetBlacklist returns a list of blacklisted IPs from SYN rate limiter.
func (ts *TCPShield) GetBlacklist() []string {
	var list []string
	now := time.Now().UnixNano()

	ts.synBuckets.ForEach(func(key uint64, entry *datastore.Entry[datastore.IPBucket]) bool {
		if entry.Value.IsBlacklisted() {
			val := entry.Value
			ip := fmt.Sprintf("%d.%d.%d.%d", byte(key>>24), byte(key>>16), byte(key>>8), byte(key))
			rem := time.Duration(val.BlacklistUntil - now).Truncate(time.Second)
			if rem < 0 {
				rem = 0
			}
			list = append(list, fmt.Sprintf("%-22s │ TCP SYN  │ %s", ip, rem))
		}
		return len(list) < 8
	})

	return list
}

// GetMaxConn returns the current max connections per IP limit.
func (ts *TCPShield) GetMaxConn() int32 {
	return ts.maxConnPerIP
}

// SetMaxConn updates the max connections per IP limit.
func (ts *TCPShield) SetMaxConn(val int32) {
	ts.maxConnPerIP = val
}

// GetIdleTimeout returns the idle timeout in seconds.
func (ts *TCPShield) GetIdleTimeout() int64 {
	return ts.idleTimeoutSec
}

// SetIdleTimeout updates the idle timeout in seconds.
func (ts *TCPShield) SetIdleTimeout(val int64) {
	ts.idleTimeoutSec = val
}
