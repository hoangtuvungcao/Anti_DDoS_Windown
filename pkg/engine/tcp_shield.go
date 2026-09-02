package engine

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sync"
	"time"

	"waf-game/pkg/datastore"
	"waf-game/pkg/packet"
	"waf-game/pkg/windivert"
)

// IsManagementPort checks if a port is a critical remote administration port (RDP, SSH, WinRM, Web Dashboard).
func IsManagementPort(port uint16) bool {
	return port == 3389 || port == 22 || port == 5985 || port == 5986 || port == 8080
}

// TCPShield implements Layer 3: Robust Stateful TCP Shield.

// Defends against SYN Floods, ACK Floods, RST/FIN Floods, Slowloris,
// Connection Starvation, and distributed botnet out-of-state attacks.
type TCPShield struct {
	mu sync.RWMutex

	// Tracked connections: Key = ConnKey (srcIP + srcPort + dstPort)
	verified *datastore.ShardedMap[TCPConnState]

	// Per-IP active connection counter
	connPerIP *datastore.ShardedMap[int32]

	// Per-Subnet (/24) active connection counter
	connPerSubnet *datastore.ShardedMap[int32]

	// Rate limiters
	synBuckets        *datastore.ShardedMap[*datastore.IPBucket]
	synSubnetBuckets  *datastore.ShardedMap[*datastore.SubnetBucket]
	connRatePerIP     *datastore.ShardedMap[*datastore.IPBucket]
	outOfStateBuckets *datastore.ShardedMap[*datastore.IPBucket]

	// Verified client IPs cache
	verifiedClients *datastore.ShardedMap[int64]

	// Settings
	maxConnPerIP     int32
	maxConnPerSubnet int32
	connRateLimitIP  int32
	idleTimeoutSec   int64
	enabled          bool
	strict           bool
	secret           uint32
	cookieKey        [32]byte
	blacklistDur     time.Duration

	// WinDivert handle
	handle *windivert.Handle

	// Engine startup time for bootstrap learning
	startTime time.Time
}

// TCPConnState tracks the lifecycle and health of a TCP connection
type TCPConnState struct {
	VerifiedAt       int64  // Unix nano when SYN was seen
	HandshakeAt      int64  // Unix nano when 3-way handshake finished (ACK seen)
	LastActivity     int64  // Unix nano of last packet
	BytesTransferred uint64 // Total payload bytes transferred
	HasPayload       bool   // Whether legitimate application data was sent
	IsHalfOpen       bool   // Waiting for client ACK to complete handshake
}

// NewTCPShield creates a new TCP Shield module.
func NewTCPShield(handle *windivert.Handle, maxConnPerIP, connRatePerIP, maxConnPerSubnet int32, idleTimeoutSec int64) *TCPShield {
	if maxConnPerIP <= 0 {
		maxConnPerIP = 50
	}
	if connRatePerIP <= 0 {
		connRatePerIP = 10
	}
	if maxConnPerSubnet <= 0 {
		maxConnPerSubnet = 150
	}
	if idleTimeoutSec <= 0 {
		idleTimeoutSec = 60
	}

	randSecret := uint32(time.Now().UnixNano())
	var key [32]byte
	_, _ = rand.Read(key[:])

	return &TCPShield{
		verified:          datastore.NewShardedMap[TCPConnState](150000),
		connPerIP:         datastore.NewShardedMap[int32](50000),
		connPerSubnet:     datastore.NewShardedMap[int32](20000),
		synBuckets:        datastore.NewShardedMap[*datastore.IPBucket](50000),
		synSubnetBuckets:  datastore.NewShardedMap[*datastore.SubnetBucket](20000),
		connRatePerIP:     datastore.NewShardedMap[*datastore.IPBucket](50000),
		outOfStateBuckets: datastore.NewShardedMap[*datastore.IPBucket](50000),
		verifiedClients:   datastore.NewShardedMap[int64](100000),
		maxConnPerIP:      maxConnPerIP,
		connRateLimitIP:   connRatePerIP,
		maxConnPerSubnet:  maxConnPerSubnet,
		idleTimeoutSec:    idleTimeoutSec,
		enabled:           true,
		strict:            false,
		secret:            randSecret,
		cookieKey:         key,
		blacklistDur:      5 * time.Minute,
		handle:            handle,
		startTime:         time.Now(),
	}
}

// TrackOutbound registers an outbound TCP connection from the server.
func (ts *TCPShield) TrackOutbound(dstIP [4]byte, dstPort, srcPort uint16) {
	ipVal := binary.BigEndian.Uint32(dstIP[:])
	connKey := uint64(ipVal)<<32 | uint64(dstPort)<<16 | uint64(srcPort)
	now := time.Now().UnixNano()
	ts.verified.Set(connKey, TCPConnState{
		VerifiedAt:   now,
		HandshakeAt:  now,
		LastActivity: now,
		HasPayload:   true,
		IsHalfOpen:   false,
	})
}

// SetStrict enables or disables strict stateful filtering (War Mode).
func (ts *TCPShield) SetStrict(val bool) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.strict = val
}

// ProcessTCP handles a TCP packet through connection tracking and rate limiting.
func (ts *TCPShield) ProcessTCP(pkt *packet.Packet, rawBuf []byte, addr *windivert.Address) FilterResult {
	ts.mu.RLock()
	enabled, strict := ts.enabled, ts.strict
	maxConnPerIP, maxConnPerSubnet := ts.maxConnPerIP, ts.maxConnPerSubnet
	connRateLimitIP := ts.connRateLimitIP
	ts.mu.RUnlock()
	if !enabled {
		return FilterPass
	}

	connKey := pkt.ConnKey()
	ipKey := pkt.IPFlowKey()
	subnetKey := uint64(pkt.SrcIPUint32() >> 8)
	now := time.Now().UnixNano()

	// 1. Fast check: is this IP already blacklisted?
	if entry, ok := ts.synBuckets.Get(ipKey); ok {
		if entry.Value.IsBlacklisted() {
			return FilterDrop
		}
	}
	if entry, ok := ts.outOfStateBuckets.Get(ipKey); ok {
		if entry.Value.IsBlacklisted() {
			return FilterDrop
		}
	}

	// 2. Drop TCP packets with invalid flag combinations
	if (pkt.IsSYN() && pkt.IsFIN()) || (pkt.IsSYN() && pkt.IsRST()) {
		return FilterDrop
	}

	// 3. Handle RST/FIN packets (Teardown)
	if pkt.IsRST() || pkt.IsFIN() {
		if _, ok := ts.verified.Get(connKey); ok {
			ts.verified.Delete(connKey)
			if entry, ok := ts.connPerIP.Get(ipKey); ok && entry.Value > 0 {
				entry.Value--
			}
			if entry, ok := ts.connPerSubnet.Get(subnetKey); ok && entry.Value > 0 {
				entry.Value--
			}
			return FilterPass
		}

		// Unsolicited RST/FIN packet (not belonging to any tracked connection)
		bucket, _ := ts.outOfStateBuckets.GetOrCreate(ipKey, func() *datastore.IPBucket {
			return datastore.NewIPBucket(30)
		})
		if !bucket.Value.Allow() {
			return FilterDrop
		}
		return FilterPass
	}

	// 4. Handle SYN packets (Connection Initiation)
	if pkt.IsSYN() {
		// A. Check SYN rate limiter per IP (uses tcp_conn_rate_per_ip from config)
		synEntry, _ := ts.synBuckets.GetOrCreate(ipKey, func() *datastore.IPBucket {
			return datastore.NewIPBucket(float64(connRateLimitIP))
		})
		if !synEntry.Value.Allow() {
			synEntry.Value.Blacklist(ts.blacklistDur)
			return FilterDrop
		}

		// B. Check SYN rate limiter per Subnet /24 (150 SYNs per second per /24)
		subnetSynEntry, _ := ts.synSubnetBuckets.GetOrCreate(subnetKey, func() *datastore.SubnetBucket {
			return datastore.NewSubnetBucket(150)
		})
		if !subnetSynEntry.Value.Allow() {
			subnetSynEntry.Value.Blacklist(ts.blacklistDur)
			return FilterDrop
		}

		// C. Check New Connection Rate per IP
		rateEntry, _ := ts.connRatePerIP.GetOrCreate(ipKey, func() *datastore.IPBucket {
			return datastore.NewIPBucket(float64(connRateLimitIP * 2))
		})
		if !rateEntry.Value.Allow() {
			rateEntry.Value.Blacklist(ts.blacklistDur)
			return FilterDrop
		}

		// D. Check Max Concurrent Connections per IP
		connEntry, _ := ts.connPerIP.GetOrCreate(ipKey, func() int32 { return 0 })
		if connEntry.Value >= maxConnPerIP {
			return FilterDrop
		}

		// E. Check Max Concurrent Connections per Subnet /24
		subnetConnEntry, _ := ts.connPerSubnet.GetOrCreate(subnetKey, func() int32 { return 0 })
		if subnetConnEntry.Value >= maxConnPerSubnet {
			return FilterDrop
		}

		// Register connection as Half-Open
		ts.verified.Set(connKey, TCPConnState{
			VerifiedAt:   now,
			LastActivity: now,
			HasPayload:   false,
			IsHalfOpen:   true,
		})
		connEntry.Value++
		subnetConnEntry.Value++

		return FilterPass
	}

	// 5. Handle Established Connection Packets (ACK, PSH-ACK, Data)
	if entry, ok := ts.verified.Get(connKey); ok {
		state := &entry.Value
		state.LastActivity = now
		entry.LastSeen = now

		// If this was half-open, client ACK completes the 3-way handshake
		if state.IsHalfOpen && pkt.IsACK() {
			state.IsHalfOpen = false
			state.HandshakeAt = now
		}

		if pkt.PayloadLen > 0 {
			state.HasPayload = true
			state.BytesTransferred += uint64(pkt.PayloadLen)
		}
		return FilterPass
	}

	// 6. Out-of-State Packet Handling (Unverified Connection Scrubber)

	// Check if this ACK contains a valid Cryptographic SYN Cookie response (RFC 4987)
	if pkt.IsACK() && pkt.AckNum > 0 {
		cookieCandidate := pkt.AckNum - 1
		if ts.ValidateSYNCookie(pkt.SrcIP, pkt.DstIP, pkt.SrcPort, pkt.DstPort, cookieCandidate) {
			ts.verified.Set(connKey, TCPConnState{
				VerifiedAt:       now,
				HandshakeAt:      now,
				LastActivity:     now,
				BytesTransferred: uint64(pkt.PayloadLen),
				HasPayload:       pkt.PayloadLen > 0,
				IsHalfOpen:       false,
			})
			connEntry, _ := ts.connPerIP.GetOrCreate(ipKey, func() int32 { return 0 })
			connEntry.Value++
			subnetConnEntry, _ := ts.connPerSubnet.GetOrCreate(subnetKey, func() int32 { return 0 })
			subnetConnEntry.Value++
			return FilterPass
		}
	}

	// Unverified ACK+data is only adopted in peace mode for connections that
	// pre-date engine startup. Strict mode fails closed against ACK/data botnets.
	if pkt.PayloadLen > 0 {
		outDataBucket, _ := ts.outOfStateBuckets.GetOrCreate(ipKey, func() *datastore.IPBucket {
			return datastore.NewIPBucket(30)
		})
		if !outDataBucket.Value.Allow() || strict {
			if outDataBucket.Value.ViolationCount() >= 8 {
				outDataBucket.Value.Blacklist(ts.blacklistDur)
			}
			return FilterDrop
		}

		ts.verified.Set(connKey, TCPConnState{
			VerifiedAt:       now,
			HandshakeAt:      now,
			LastActivity:     now,
			BytesTransferred: uint64(pkt.PayloadLen),
			HasPayload:       true,
			IsHalfOpen:       false,
		})
		return FilterPass
	}

	// Rate limit pure zero-payload ACK flood
	outBucket, _ := ts.outOfStateBuckets.GetOrCreate(ipKey, func() *datastore.IPBucket {
		limit := float64(50)
		if strict {
			limit = 10
		}
		return datastore.NewIPBucket(limit)
	})

	if !outBucket.Value.Allow() {
		return FilterDrop
	}

	if strict {
		return FilterDrop
	}

	return FilterPass
}

// ReapIdleConnections removes idle connections (> idleTimeoutSec) and decrements counters.
func (ts *TCPShield) ReapIdleConnections() int64 {
	ts.mu.RLock()
	idleTimeoutSec := ts.idleTimeoutSec
	ts.mu.RUnlock()
	idleCutoff := time.Duration(idleTimeoutSec) * time.Second
	return ts.verified.SweepWithCallback(idleCutoff, func(key uint64, state TCPConnState) {
		dstPort := uint16((key >> 16) & 0xFFFF)
		if IsManagementPort(dstPort) {
			return // Never kill idle management sessions (RDP/SSH)
		}
		ipVal := uint32(key >> 32)
		ipKey := uint64(ipVal)
		subnetKey := uint64(ipVal >> 8)

		if cEntry, ok := ts.connPerIP.Get(ipKey); ok && cEntry.Value > 0 {
			cEntry.Value--
		}
		if sEntry, ok := ts.connPerSubnet.Get(subnetKey); ok && sEntry.Value > 0 {
			sEntry.Value--
		}
	})
}

// ReapHalfOpenAndZeroPayload cleans up incomplete connections and unverified zero-payload connections.
func (ts *TCPShield) ReapHalfOpenAndZeroPayload() int64 {
	now := time.Now().UnixNano()
	halfOpenCutoff := now - int64(15*time.Second)    // 15s timeout for completing SYN handshake
	zeroPayloadCutoff := now - int64(60*time.Second) // 60s timeout for established connection to send payload

	var toDelete []uint64
	ts.verified.ForEach(func(key uint64, entry *datastore.Entry[TCPConnState]) bool {
		dstPort := uint16((key >> 16) & 0xFFFF)
		if IsManagementPort(dstPort) {
			return true // Never reap management sessions
		}
		state := entry.Value
		if state.IsHalfOpen && state.VerifiedAt < halfOpenCutoff {
			toDelete = append(toDelete, key)
		} else if !state.IsHalfOpen && !state.HasPayload && state.HandshakeAt > 0 && state.HandshakeAt < zeroPayloadCutoff {
			toDelete = append(toDelete, key)
		}
		return true
	})

	for _, key := range toDelete {
		ts.verified.Delete(key)
		ipVal := uint32(key >> 32)
		ipKey := uint64(ipVal)
		subnetKey := uint64(ipVal >> 8)

		if cEntry, ok := ts.connPerIP.Get(ipKey); ok && cEntry.Value > 0 {
			cEntry.Value--
		}
		if sEntry, ok := ts.connPerSubnet.Get(subnetKey); ok && sEntry.Value > 0 {
			sEntry.Value--
		}
	}

	return int64(len(toDelete))
}

// ReapSlowlorisConnections forcibly terminates connections that hold open sockets but send no/low data.
func (ts *TCPShield) ReapSlowlorisConnections() int64 {
	now := time.Now().UnixNano()
	slowlorisCutoff := now - int64(15*time.Second) // 15 seconds threshold

	var toDelete []uint64
	ts.verified.ForEach(func(key uint64, entry *datastore.Entry[TCPConnState]) bool {
		dstPort := uint16((key >> 16) & 0xFFFF)
		if IsManagementPort(dstPort) {
			return true // Never kill management sessions (RDP/SSH)
		}
		state := entry.Value
		// Established connection older than 15s with less than 64 bytes transferred
		if !state.IsHalfOpen && state.HandshakeAt > 0 && state.HandshakeAt < slowlorisCutoff && state.BytesTransferred < 64 {
			toDelete = append(toDelete, key)
		}
		return true
	})

	for _, key := range toDelete {
		ts.verified.Delete(key)
		ipVal := uint32(key >> 32)
		ipKey := uint64(ipVal)
		subnetKey := uint64(ipVal >> 8)
		if cEntry, ok := ts.connPerIP.Get(ipKey); ok && cEntry.Value > 0 {
			cEntry.Value--
		}
		if sEntry, ok := ts.connPerSubnet.Get(subnetKey); ok && sEntry.Value > 0 {
			sEntry.Value--
		}
	}

	return int64(len(toDelete))
}

// GenerateSYNCookie generates a stateless cryptographic 32-bit initial sequence number (RFC 4987)
func (ts *TCPShield) GenerateSYNCookie(srcIP [4]byte, dstIP [4]byte, srcPort, dstPort uint16) uint32 {
	tMinute := uint32(time.Now().Unix() / 60)
	timeBits := (tMinute & 0x1F) << 27 // 5 bits for time (32 minutes cycle)
	mssBits := uint32(3) << 24         // 3 bits for MSS index (e.g. index 3 = 1460)

	// Hash 4-tuple + secret + time
	var buf [16]byte
	copy(buf[0:4], srcIP[:])
	copy(buf[4:8], dstIP[:])
	binary.BigEndian.PutUint16(buf[8:10], srcPort)
	binary.BigEndian.PutUint16(buf[10:12], dstPort)
	binary.BigEndian.PutUint32(buf[12:16], tMinute)

	mac := hmac.New(sha256.New, ts.cookieKey[:])
	mac.Write(buf[:])
	hash := mac.Sum(nil)
	hashBits := binary.BigEndian.Uint32(hash[0:4]) & 0x00FFFFFF // 24 bits

	return timeBits | mssBits | hashBits
}

// ValidateSYNCookie checks if a client's ACK number matches a valid SYN cookie.
func (ts *TCPShield) ValidateSYNCookie(srcIP [4]byte, dstIP [4]byte, srcPort, dstPort uint16, cookie uint32) bool {
	cookieTimeBits := (cookie >> 27) & 0x1F
	cookieHashBits := cookie & 0x00FFFFFF

	currentMinute := uint32(time.Now().Unix() / 60)

	// Check current minute and previous minute (allows 2-minute window for packet delay)
	for diff := uint32(0); diff <= 2; diff++ {
		tMinute := currentMinute - diff
		if (tMinute & 0x1F) == cookieTimeBits {
			var buf [16]byte
			copy(buf[0:4], srcIP[:])
			copy(buf[4:8], dstIP[:])
			binary.BigEndian.PutUint16(buf[8:10], srcPort)
			binary.BigEndian.PutUint16(buf[10:12], dstPort)
			binary.BigEndian.PutUint32(buf[12:16], tMinute)

			mac := hmac.New(sha256.New, ts.cookieKey[:])
			mac.Write(buf[:])
			hash := mac.Sum(nil)
			expectedHashBits := binary.BigEndian.Uint32(hash[0:4]) & 0x00FFFFFF

			if expectedHashBits == cookieHashBits {
				return true
			}
		}
	}
	return false
}

// GetVerifiedCount returns the number of tracked TCP connections.
func (ts *TCPShield) GetVerifiedCount() int64 {
	return ts.verified.Count()
}

// GetBlacklist returns a list of blacklisted IPs from TCP rate limiters.
func (ts *TCPShield) GetBlacklist() []string {
	var list []string
	now := time.Now().UnixNano()

	ts.synBuckets.ForEach(func(key uint64, entry *datastore.Entry[*datastore.IPBucket]) bool {
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

	// Bug fix: also include out-of-state blacklisted IPs
	ts.outOfStateBuckets.ForEach(func(key uint64, entry *datastore.Entry[*datastore.IPBucket]) bool {
		if entry.Value.IsBlacklisted() {
			val := entry.Value
			ip := fmt.Sprintf("%d.%d.%d.%d", byte(key>>24), byte(key>>16), byte(key>>8), byte(key))
			rem := time.Duration(val.BlacklistUntil - now).Truncate(time.Second)
			if rem < 0 {
				rem = 0
			}
			list = append(list, fmt.Sprintf("%-22s │ TCP OOS  │ %s", ip, rem))
		}
		return len(list) < 16
	})

	return list
}

// GetMaxConn returns the current max connections per IP limit.
func (ts *TCPShield) GetMaxConn() int32 {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	return ts.maxConnPerIP
}

// SetMaxConn updates the max connections per IP limit.
func (ts *TCPShield) SetMaxConn(val int32) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.maxConnPerIP = val
}

// GetIdleTimeout returns the idle timeout in seconds.
func (ts *TCPShield) GetIdleTimeout() int64 {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	return ts.idleTimeoutSec
}

// SetIdleTimeout updates the idle timeout in seconds.
func (ts *TCPShield) SetIdleTimeout(val int64) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.idleTimeoutSec = val
}
