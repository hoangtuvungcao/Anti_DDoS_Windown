package engine

import (
	"bytes"
	"encoding/hex"
	"sync"
	"time"

	"waf-game/pkg/datastore"
	"waf-game/pkg/packet"
)

// CustomGameRule holds a custom port protection rule
type CustomGameRule struct {
	Port         uint16
	Protocol     string
	Game         string
	SignatureHex string
	Signature    []byte
	AllowPPS     int
}

// GameShield implements Layer 4.5: Game Protocol & Query Flood Shield.
// Detects and throttles query reflection floods (Valve A2S, SA-MP, RakNet, etc.)
type GameShield struct {
	mu sync.RWMutex

	enabled bool

	// Query rate limiters per IP (5 PPS limit for game info queries)
	queryBuckets *datastore.ShardedMap[*datastore.IPBucket]

	// Custom game rules indexed by port
	customRules map[uint16][]CustomGameRule

	// Signatures
	a2sHeader      []byte
	sampHeader     []byte
	raknetPingByte byte
}

// NewGameShield creates a new GameShield instance.
func NewGameShield(customRules []CustomGameRule) *GameShield {
	gs := &GameShield{
		enabled:        true,
		queryBuckets:   datastore.NewShardedMap[*datastore.IPBucket](50000),
		customRules:    make(map[uint16][]CustomGameRule),
		a2sHeader:      []byte{0xFF, 0xFF, 0xFF, 0xFF},
		sampHeader:     []byte{'S', 'A', 'M', 'P'},
		raknetPingByte: 0x01,
	}

	for _, r := range customRules {
		if r.SignatureHex != "" {
			sigBytes, err := hex.DecodeString(r.SignatureHex)
			if err == nil {
				r.Signature = sigBytes
			}
		}
		gs.customRules[r.Port] = append(gs.customRules[r.Port], r)
	}

	return gs
}

// SetEnabled enables or disables the game shield.
func (gs *GameShield) SetEnabled(enabled bool) {
	gs.mu.Lock()
	defer gs.mu.Unlock()
	gs.enabled = enabled
}

// CheckGamePacket inspects UDP payload for game query floods or protocol violations.
// Returns FilterDrop if it is a query flood or violates rule, FilterPass otherwise.
func (gs *GameShield) CheckGamePacket(pkt *packet.Packet, payload []byte) FilterResult {
	gs.mu.RLock()
	enabled := gs.enabled
	gs.mu.RUnlock()
	if !enabled || len(payload) == 0 {
		return FilterPass
	}

	ipKey := pkt.IPFlowKey()

	// 1. Check Valve Source Engine / Steam Query Floods (A2S_INFO, A2S_PLAYER, A2S_RULES)
	// Query packets start with 0xFF 0xFF 0xFF 0xFF followed by query byte
	if len(payload) >= 5 && bytes.Equal(payload[:4], gs.a2sHeader) {
		op := payload[4]
		// 0x54 = A2S_INFO ('T'), 0x55 = A2S_PLAYER ('U'), 0x56 = A2S_RULES ('V'),
		// 0x57 = A2S_SERVERQUERY_GETCHALLENGE ('W'), 0x69 = A2S_PING ('i'), 0x71 = A2A_PING ('q')
		if op == 0x54 || op == 0x55 || op == 0x56 || op == 0x57 || op == 0x69 || op == 0x71 {
			bucket, _ := gs.queryBuckets.GetOrCreate(ipKey, func() *datastore.IPBucket {
				return datastore.NewIPBucket(5) // Max 5 query packets/sec per IP
			})

			if !bucket.Value.Allow() {
				bucket.Value.Blacklist(60 * time.Second)
				return FilterDrop
			}
		}
	}

	// 2. Check SA-MP (San Andreas Multiplayer) / OpenMP Query Floods
	// Packet starts with 'S','A','M','P' (4 bytes), followed by 4-byte IP, 2-byte Port, 1-byte Opcode
	if len(payload) >= 11 && bytes.Equal(payload[:4], gs.sampHeader) {
		op := payload[10]
		// 'i' = Info, 'p' = Ping, 'c' = Players, 'r' = Rules, 'd' = Detailed Players
		if op == 'i' || op == 'p' || op == 'c' || op == 'r' || op == 'd' {
			bucket, _ := gs.queryBuckets.GetOrCreate(ipKey, func() *datastore.IPBucket {
				return datastore.NewIPBucket(5)
			})

			if !bucket.Value.Allow() {
				bucket.Value.Blacklist(60 * time.Second)
				return FilterDrop
			}
		}
	}

	// 3. Check Minecraft Bedrock / RakNet Unconnected Ping Floods
	// Packet 0x01 (ID_UNCONNECTED_PING) or 0x02 (ID_UNCONNECTED_PING_OPEN_CONNECTIONS)
	if (payload[0] == 0x01 || payload[0] == 0x02) && len(payload) >= 9 {
		bucket, _ := gs.queryBuckets.GetOrCreate(ipKey, func() *datastore.IPBucket {
			return datastore.NewIPBucket(10)
		})

		if !bucket.Value.Allow() {
			bucket.Value.Blacklist(60 * time.Second)
			return FilterDrop
		}
	}

	// 4. Check Repeated Byte Floods (e.g. 1000 bytes of 0x00, 0xFF, 'A', or 0x55 synthetic bot spam)
	if len(payload) >= 32 && isRepeatedBytePattern(payload) {
		bucket, _ := gs.queryBuckets.GetOrCreate(ipKey, func() *datastore.IPBucket {
			return datastore.NewIPBucket(3) // Strict 3 PPS for repeated byte garbage
		})

		if !bucket.Value.Allow() {
			bucket.Value.Blacklist(120 * time.Second)
			return FilterDrop
		}
	}

	// 5. Custom Game Rules matching port
	gs.mu.RLock()
	rules, hasRules := gs.customRules[pkt.DstPort]
	gs.mu.RUnlock()

	if hasRules {
		for _, rule := range rules {
			if len(rule.Signature) > 0 {
				if bytes.Contains(payload, rule.Signature) {
					if rule.AllowPPS > 0 {
						bucket, _ := gs.queryBuckets.GetOrCreate(ipKey, func() *datastore.IPBucket {
							return datastore.NewIPBucket(float64(rule.AllowPPS))
						})
						if !bucket.Value.Allow() {
							return FilterDrop
						}
					}
				}
			}
		}
	}

	return FilterPass
}

// isRepeatedBytePattern checks if the payload is composed of identical repeated bytes
func isRepeatedBytePattern(payload []byte) bool {
	first := payload[0]
	// Fast check first 32 bytes
	for i := 1; i < 32; i++ {
		if payload[i] != first {
			return false
		}
	}
	// Check remaining bytes
	for i := 32; i < len(payload); i++ {
		if payload[i] != first {
			return false
		}
	}
	return true
}

// Sweep removes expired query rate limiting buckets.
func (gs *GameShield) Sweep(ttl time.Duration) int64 {
	return gs.queryBuckets.Sweep(ttl)
}
