package engine

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"waf-game/pkg/datastore"
	"waf-game/pkg/packet"
	"waf-game/pkg/windivert"
)

// TCPShield implements Layer 3: Robust Stateful TCP Shield.

// Defends against SYN Floods, ACK Floods, RST/FIN Floods, Slowloris,
// Connection Starvation, and distributed botnet out-of-state attacks.
type TCPShield struct {
	mu sync.RWMutex

	// Tracked connections: Key = ConnKey (srcIP + srcPort + dstPort)
	verified *datastore.ShardedMap[TCPConnState]

	// Per-IP active connection counter
	connPerIP *datastore.ShardedMap[*atomic.Int32]

	// Per-Subnet (/24) active connection counter
	connPerSubnet *datastore.ShardedMap[*atomic.Int32]

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
	Counted          bool   // Included in inbound per-IP/subnet connection counters
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
		connPerIP:         datastore.NewShardedMap[*atomic.Int32](50000),
		connPerSubnet:     datastore.NewShardedMap[*atomic.Int32](20000),
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

// ObserveTCP learns TCP state without enforcing limits. PEACE/ELEVATED calls
// this before reinjection so sessions that pre-date a switch to WAR remain
// established instead of being misclassified as out-of-state. An unseen ACK is
// adopted only when the Windows kernel confirms the exact connection tuple.
func (ts *TCPShield) ObserveTCP(pkt *packet.Packet, kernelEstablished bool) {
	if pkt == nil || pkt.Protocol != packet.ProtoTCP {
		return
	}
	connKey := pkt.ConnKey()
	if pkt.IsRST() || pkt.IsFIN() {
		ts.deleteConnection(connKey)
		return
	}

	now := time.Now().UnixNano()
	if pkt.IsSYN() && !pkt.IsSYNACK() {
		_, created := ts.verified.GetOrCreate(connKey, func() TCPConnState {
			return TCPConnState{
				VerifiedAt:   now,
				LastActivity: now,
				IsHalfOpen:   true,
				Counted:      true,
			}
		})
		if created {
			ts.incrementConnectionCounters(pkt.IPFlowKey(), uint64(pkt.SrcIPUint32()>>8))
		}
		return
	}
	if !pkt.IsACK() && !pkt.IsSYNACK() {
		return
	}

	_, exists := ts.verified.GetValue(connKey)
	if !exists && !kernelEstablished {
		// Never teach arbitrary out-of-state ACK floods as trusted traffic. Only
		// flows confirmed by Windows may predate shield startup.
		return
	}
	newState := TCPConnState{
		VerifiedAt:       now,
		HandshakeAt:      now,
		LastActivity:     now,
		BytesTransferred: uint64(pkt.PayloadLen),
		HasPayload:       pkt.PayloadLen > 0,
		Counted:          true,
	}
	if exists {
		ts.verified.UpdateExisting(connKey, func(state TCPConnState) TCPConnState {
			state.LastActivity = now
			state.IsHalfOpen = false
			if state.HandshakeAt == 0 {
				state.HandshakeAt = now
			}
			if pkt.PayloadLen > 0 {
				state.HasPayload = true
				state.BytesTransferred += uint64(pkt.PayloadLen)
			}
			return state
		})
		return
	}
	ts.verified.Set(connKey, newState)
	ts.incrementConnectionCounters(pkt.IPFlowKey(), uint64(pkt.SrcIPUint32()>>8))
}

func (ts *TCPShield) incrementConnectionCounters(ipKey, subnetKey uint64) {
	connEntry, _ := ts.connPerIP.GetOrCreate(ipKey, func() *atomic.Int32 { return &atomic.Int32{} })
	connEntry.Value.Add(1)
	subnetEntry, _ := ts.connPerSubnet.GetOrCreate(subnetKey, func() *atomic.Int32 { return &atomic.Int32{} })
	subnetEntry.Value.Add(1)
}

func (ts *TCPShield) decrementConnectionCounters(ipKey, subnetKey uint64) {
	if count, ok := ts.connPerIP.Get(ipKey); ok {
		decrementNonNegative(count.Value)
	}
	if count, ok := ts.connPerSubnet.Get(subnetKey); ok {
		decrementNonNegative(count.Value)
	}
}

func (ts *TCPShield) deleteConnection(connKey uint64) bool {
	state, ok := ts.verified.GetValue(connKey)
	if !ok || !ts.verified.Delete(connKey) {
		return false
	}
	if state.Counted {
		ipKey := uint64(uint32(connKey >> 32))
		ts.decrementConnectionCounters(ipKey, uint64(uint32(connKey>>32)>>8))
	}
	return true
}

func decrementNonNegative(counter *atomic.Int32) {
	for {
		current := counter.Load()
		if current <= 0 || counter.CompareAndSwap(current, current-1) {
			return
		}
	}
}

func reserveConnection(counter *atomic.Int32, limit int32) bool {
	for {
		current := counter.Load()
		if current >= limit {
			return false
		}
		if counter.CompareAndSwap(current, current+1) {
			return true
		}
	}
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
	// Invalid combinations are rejected even if an attacker guesses an existing
	// tuple. Normal established TCP never emits these flag combinations.
	if (pkt.IsSYN() && pkt.IsFIN()) || (pkt.IsSYN() && pkt.IsRST()) {
		return FilterDrop
	}

	// Established traffic always wins over dynamic flood blacklists. Windows
	// still validates TCP sequence/state after reinjection, while the shield keeps
	// rate-limiting new SYNs from the same address.
	if _, ok := ts.verified.GetValue(connKey); ok {
		if pkt.IsRST() || pkt.IsFIN() {
			ts.deleteConnection(connKey)
			return FilterPass
		}
		ts.verified.UpdateExisting(connKey, func(state TCPConnState) TCPConnState {
			state.LastActivity = now
			if state.IsHalfOpen && pkt.IsACK() {
				state.IsHalfOpen = false
				state.HandshakeAt = now
			}
			if pkt.PayloadLen > 0 {
				state.HasPayload = true
				state.BytesTransferred += uint64(pkt.PayloadLen)
			}
			return state
		})
		return FilterPass
	}

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

	// 3. Handle untracked RST/FIN packets.
	if pkt.IsRST() || pkt.IsFIN() {
		// Unsolicited RST/FIN packet (not belonging to any tracked connection)
		bucket, _ := ts.outOfStateBuckets.GetOrCreate(ipKey, func() *datastore.IPBucket {
			return datastore.NewIPBucket(30)
		})
		if !bucket.Value.Allow() {
			return FilterDrop
		}
		return FilterPass
	}

	// 4. Handle an untracked inbound SYN-ACK. A legitimate outbound connection
	// is registered by the outbound sniffer before its reply arrives and takes
	// the verified fast path above. Never promote an unsolicited SYN-ACK to a
	// trusted connection: botnets can forge one without completing a handshake.
	if pkt.IsSYNACK() {
		bucket, _ := ts.outOfStateBuckets.GetOrCreate(ipKey, func() *datastore.IPBucket {
			limit := float64(60)
			if strict {
				limit = 30
			}
			return datastore.NewIPBucket(limit)
		})
		if !bucket.Value.Allow() {
			return FilterDrop
		}
		return FilterPass
	}

	// 5. Handle Inbound SYN packets from Clients (Connection Initiation)
	if pkt.IsSYN() {
		// A. Check SYN rate limiter per IP (uses tcp_conn_rate_per_ip from config)
		synEntry, _ := ts.synBuckets.GetOrCreate(ipKey, func() *datastore.IPBucket {
			return datastore.NewIPBucket(float64(connRateLimitIP))
		})
		if !synEntry.Value.Allow() {
			if strict && synEntry.Value.ViolationCount() >= 100 {
				synEntry.Value.Blacklist(30 * time.Second)
			}
			return FilterDrop
		}

		// B. Check SYN rate limiter per Subnet /24 (150 SYNs per second per /24)
		subnetSynEntry, _ := ts.synSubnetBuckets.GetOrCreate(subnetKey, func() *datastore.SubnetBucket {
			return datastore.NewSubnetBucket(150)
		})
		if !subnetSynEntry.Value.Allow() {
			if strict && subnetSynEntry.Value.ViolationCount() >= 300 {
				subnetSynEntry.Value.Blacklist(30 * time.Second)
			}
			return FilterDrop
		}

		// C. Check New Connection Rate per IP
		rateEntry, _ := ts.connRatePerIP.GetOrCreate(ipKey, func() *datastore.IPBucket {
			return datastore.NewIPBucket(float64(connRateLimitIP * 2))
		})
		if !rateEntry.Value.Allow() {
			if strict && rateEntry.Value.ViolationCount() >= 100 {
				rateEntry.Value.Blacklist(30 * time.Second)
			}
			return FilterDrop
		}

		// D. Check Max Concurrent Connections per IP
		connEntry, _ := ts.connPerIP.GetOrCreate(ipKey, func() *atomic.Int32 { return &atomic.Int32{} })
		if !reserveConnection(connEntry.Value, maxConnPerIP) {
			return FilterDrop
		}

		// E. Check Max Concurrent Connections per Subnet /24
		subnetConnEntry, _ := ts.connPerSubnet.GetOrCreate(subnetKey, func() *atomic.Int32 { return &atomic.Int32{} })
		if !reserveConnection(subnetConnEntry.Value, maxConnPerSubnet) {
			decrementNonNegative(connEntry.Value)
			return FilterDrop
		}

		// Register connection as Half-Open
		_, created := ts.verified.GetOrCreate(connKey, func() TCPConnState {
			return TCPConnState{
				VerifiedAt:   now,
				LastActivity: now,
				HasPayload:   false,
				IsHalfOpen:   true,
				Counted:      true,
			}
		})
		if !created {
			// Another worker admitted the same tuple between the fast-path lookup
			// and reservation. Roll back both reservations to keep counts exact.
			decrementNonNegative(connEntry.Value)
			decrementNonNegative(subnetConnEntry.Value)
		}
		return FilterPass
	}

	// 6. Out-of-State Packet Handling (Unverified Connection Scrubber)

	// Check if this ACK contains a valid Cryptographic SYN Cookie response (RFC 4987)
	if pkt.IsACK() && pkt.AckNum > 0 {
		cookieCandidate := pkt.AckNum - 1
		if ts.ValidateSYNCookie(pkt.SrcIP, pkt.DstIP, pkt.SrcPort, pkt.DstPort, cookieCandidate) {
			_, created := ts.verified.GetOrCreate(connKey, func() TCPConnState {
				return TCPConnState{
					VerifiedAt:       now,
					HandshakeAt:      now,
					LastActivity:     now,
					BytesTransferred: uint64(pkt.PayloadLen),
					HasPayload:       pkt.PayloadLen > 0,
					IsHalfOpen:       false,
					Counted:          true,
				}
			})
			if created {
				ts.incrementConnectionCounters(ipKey, subnetKey)
			}
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

		_, created := ts.verified.GetOrCreate(connKey, func() TCPConnState {
			return TCPConnState{
				VerifiedAt:       now,
				HandshakeAt:      now,
				LastActivity:     now,
				BytesTransferred: uint64(pkt.PayloadLen),
				HasPayload:       true,
				IsHalfOpen:       false,
				Counted:          true,
			}
		})
		if created {
			ts.incrementConnectionCounters(ipKey, subnetKey)
		}
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
		if !state.Counted {
			return
		}
		ipVal := uint32(key >> 32)
		ipKey := uint64(ipVal)
		subnetKey := uint64(ipVal >> 8)

		ts.decrementConnectionCounters(ipKey, subnetKey)
	})
}

// ReapHalfOpenAndZeroPayload cleans up incomplete connections and unverified zero-payload connections.
func (ts *TCPShield) ReapHalfOpenAndZeroPayload() int64 {
	now := time.Now().UnixNano()
	halfOpenCutoff := now - int64(30*time.Second)     // 30s timeout for completing SYN handshake
	zeroPayloadCutoff := now - int64(120*time.Second) // 120s timeout for established connection to send payload
	ts.mu.RLock()
	strict := ts.strict
	ts.mu.RUnlock()
	if strict {
		zeroPayloadCutoff = now - int64(45*time.Second)
	}

	var toDelete []uint64
	ts.verified.ForEach(func(key uint64, entry *datastore.Entry[TCPConnState]) bool {
		state := entry.Value
		if state.IsHalfOpen && state.VerifiedAt < halfOpenCutoff {
			toDelete = append(toDelete, key)
		} else if !state.IsHalfOpen && !state.HasPayload && state.HandshakeAt > 0 && state.HandshakeAt < zeroPayloadCutoff {
			toDelete = append(toDelete, key)
		}
		return true
	})

	for _, key := range toDelete {
		ts.deleteConnection(key)
	}

	return int64(len(toDelete))
}

// ReapSlowlorisConnections forcibly terminates connections that hold open sockets but send no/low data.
func (ts *TCPShield) ReapSlowlorisConnections() int64 {
	now := time.Now().UnixNano()
	slowlorisCutoff := now - int64(120*time.Second) // 120s threshold in peace mode
	ts.mu.RLock()
	strict := ts.strict
	ts.mu.RUnlock()
	if strict {
		slowlorisCutoff = now - int64(30*time.Second) // 30s threshold under War mode DDoS
	}

	var toDelete []uint64
	ts.verified.ForEach(func(key uint64, entry *datastore.Entry[TCPConnState]) bool {
		state := entry.Value
		// Established connection older than threshold with less than 64 bytes transferred
		if !state.IsHalfOpen && state.HandshakeAt > 0 && state.HandshakeAt < slowlorisCutoff && state.BytesTransferred < 64 {
			toDelete = append(toDelete, key)
		}
		return true
	})

	for _, key := range toDelete {
		ts.deleteConnection(key)
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

// IsVerified checks if a TCP connection is established and verified.
func (ts *TCPShield) IsVerified(connKey uint64) bool {
	_, ok := ts.verified.Get(connKey)
	return ok
}

// GetVerifiedCount returns the number of tracked TCP connections.
func (ts *TCPShield) GetVerifiedCount() int64 {
	return ts.verified.Count()
}

// EnforceCapacity applies the configured aggregate cache ceiling across TCP
// connection and flood-accounting state stores.
func (ts *TCPShield) EnforceCapacity(maxEntries int) int64 {
	if maxEntries < 1000 {
		maxEntries = 1000
	}
	var removed int64
	removed += ts.verified.EvictOldestWithCallback(maxEntries/2, func(key uint64, state TCPConnState) {
		if !state.Counted {
			return
		}
		ipKey := uint64(uint32(key >> 32))
		subnetKey := uint64(uint32(key>>32) >> 8)
		ts.decrementConnectionCounters(ipKey, subnetKey)
	})
	perAuxiliary := maxEntries / 14
	removed += ts.connPerIP.EvictOldest(perAuxiliary)
	removed += ts.connPerSubnet.EvictOldest(perAuxiliary)
	removed += ts.synBuckets.EvictOldest(perAuxiliary)
	removed += ts.synSubnetBuckets.EvictOldest(perAuxiliary)
	removed += ts.connRatePerIP.EvictOldest(perAuxiliary)
	removed += ts.outOfStateBuckets.EvictOldest(perAuxiliary)
	removed += ts.verifiedClients.EvictOldest(perAuxiliary)
	return removed
}

// GetBlacklist returns a list of blacklisted IPs from TCP rate limiters.
func (ts *TCPShield) GetBlacklist() []string {
	var list []string
	now := time.Now().UnixNano()

	ts.synBuckets.ForEach(func(key uint64, entry *datastore.Entry[*datastore.IPBucket]) bool {
		if entry.Value.IsBlacklisted() {
			val := entry.Value
			ip := fmt.Sprintf("%d.%d.%d.%d", byte(key>>24), byte(key>>16), byte(key>>8), byte(key))
			rem := time.Duration(val.BlacklistDeadline() - now).Truncate(time.Second)
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
			rem := time.Duration(val.BlacklistDeadline() - now).Truncate(time.Second)
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
