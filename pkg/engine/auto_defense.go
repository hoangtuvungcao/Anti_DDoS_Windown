package engine

import (
	"fmt"
	"math"
	"sync"
	"time"

	"waf-game/pkg/datastore"
	"waf-game/pkg/stats"
)

// AttackVector represents identified DDoS attack patterns.
type AttackVector string

const (
	VectorNone             AttackVector = "NONE"
	VectorSynFlood         AttackVector = "TCP SYN FLOOD"
	VectorSubnetBotnet     AttackVector = "DISTRIBUTED /24 BOTNET"
	VectorCarpetBombing    AttackVector = "SUBNET CARPET BOMBING"
	VectorUdpAmplification AttackVector = "UDP REFLECTION / AMP"
	VectorGameQueryFlood   AttackVector = "PROTOCOL QUERY FLOOD"
	VectorTcpOutOfState    AttackVector = "TCP OUT-OF-STATE / ACK"
	VectorUdpEntropy       AttackVector = "UDP HIGH-ENTROPY FLOOD"
	VectorFragmentFlood    AttackVector = "IP FRAGMENT FLOOD"
)

// OffenderRecord tracks repeat attack history for graduated auto-ban.
type OffenderRecord struct {
	OffenseCount int32
	FirstSeen    int64
	LastOffense  int64
	BanLevel     int32 // 1=60s, 2=5m, 3=1h, 4=24h
}

// AutoDefense provides adaptive AI-like baseline auto-tuning and intelligent threat mitigation.
type AutoDefense struct {
	mu sync.RWMutex

	// Baseline traffic tracking (Exponential Moving Average)
	avgPeacePPS  float64
	avgPeaceBPS  float64
	sampleCount  int64
	alpha        float64 // EMA smoothing factor (e.g. 0.05)
	autoTuneMode bool

	// Dynamic attack vectors currently active
	activeVectors   []AttackVector
	primaryVector   AttackVector
	lastVectorAlert time.Time

	// Repeat offender tracking
	offenders *datastore.ShardedMap[*OffenderRecord]

	// Metrics reference
	metrics *stats.Metrics

	// Logger
	logger interface {
		Println(v ...interface{})
		Printf(format string, v ...interface{})
	}
}

// NewAutoDefense initializes the universal auto-defense heuristics engine.
func NewAutoDefense(metrics *stats.Metrics, logger interface {
	Println(v ...interface{})
	Printf(format string, v ...interface{})
}) *AutoDefense {
	return &AutoDefense{
		avgPeacePPS:   100,
		avgPeaceBPS:   102400,
		alpha:         0.05,
		autoTuneMode:  true,
		primaryVector: VectorNone,
		offenders:     datastore.NewShardedMap[*OffenderRecord](50000),
		metrics:       metrics,
		logger:        logger,
	}
}

// GetPortProfile returns the dynamic protection status for any open port.
func (ad *AutoDefense) GetPortProfile(port uint16) string {
	return "UNIVERSAL_PORT_SHIELD (Active 1-65535)"
}

// EvaluateBaselineAndUpdate adapts the baseline during Peace mode and classifies attacks during War mode.
func (ad *AutoDefense) EvaluateBaselineAndUpdate(isWar bool) (recTriggerPPS, recTriggerBPS uint64) {
	ad.mu.Lock()
	defer ad.mu.Unlock()

	snapPPS := float64(ad.metrics.SnapPPS.Load())
	snapBPS := float64(ad.metrics.SnapBPS.Load())

	// In Peace Mode, update Exponential Moving Average of normal traffic
	if !isWar {
		if snapPPS > 0 {
			ad.avgPeacePPS = (ad.alpha * snapPPS) + ((1 - ad.alpha) * ad.avgPeacePPS)
			ad.avgPeaceBPS = (ad.alpha * snapBPS) + ((1 - ad.alpha) * ad.avgPeaceBPS)
			ad.sampleCount++
		}
		ad.primaryVector = VectorNone
		ad.activeVectors = ad.activeVectors[:0]
	} else {
		// In War Mode, classify the primary attack vector
		ad.classifyAttackVector()
	}

	// Calculate recommended dynamic thresholds (Baseline * 3x margin, min 2500 PPS)
	recPPS := uint64(math.Max(2500, ad.avgPeacePPS*3.0))
	recBPS := uint64(math.Max(26214400, ad.avgPeaceBPS*3.0)) // min 25 MB/s

	return recPPS, recBPS
}

// classifyAttackVector inspects real-time drop metrics to identify what DDoS is occurring.
func (ad *AutoDefense) classifyAttackVector() {
	var vectors []AttackVector

	if ad.metrics.BotnetDetected.Load() {
		vectors = append(vectors, VectorSubnetBotnet)
	}
	if ad.metrics.SnapSubnet.Load() > 20 {
		if ad.metrics.SnapL2.Load() > 50 {
			// Carpet bombing: many closed ports hit across the subnet — most specific, check first
			vectors = append(vectors, VectorCarpetBombing)
		}
		if !ad.metrics.BotnetDetected.Load() {
			// Subnet flooding without confirmed global botnet threshold
			vectors = append(vectors, VectorSubnetBotnet)
		}
	}
	if ad.metrics.SnapReflection.Load() > 20 {
		vectors = append(vectors, VectorUdpAmplification)
	}
	if ad.metrics.SnapGameQuery.Load() > 10 {
		vectors = append(vectors, VectorGameQueryFlood)
	}
	if ad.metrics.SnapOutOfState.Load() > 20 {
		vectors = append(vectors, VectorTcpOutOfState)
	}
	if ad.metrics.SnapL3.Load() > 50 && ad.metrics.SnapOutOfState.Load() <= 20 {
		vectors = append(vectors, VectorSynFlood)
	}
	if ad.metrics.SnapL1.Load() > 50 {
		vectors = append(vectors, VectorFragmentFlood)
	}

	ad.activeVectors = vectors

	if len(vectors) > 0 {
		ad.primaryVector = vectors[0]
	} else {
		ad.primaryVector = "GENERIC FLOOD"
	}
}

// GetPrimaryAttackVector returns the currently diagnosed attack pattern.
func (ad *AutoDefense) GetPrimaryAttackVector() AttackVector {
	ad.mu.RLock()
	defer ad.mu.RUnlock()
	return ad.primaryVector
}

// GetActiveAttackVectors returns all active identified DDoS patterns.
func (ad *AutoDefense) GetActiveAttackVectors() []AttackVector {
	ad.mu.RLock()
	defer ad.mu.RUnlock()
	res := make([]AttackVector, len(ad.activeVectors))
	copy(res, ad.activeVectors)
	return res
}

// CalculateGraduatedBan calculates ban duration for an IP based on repeat offense history.
func (ad *AutoDefense) CalculateGraduatedBan(ipKey uint64) time.Duration {
	now := time.Now().UnixNano()
	entry, isNew := ad.offenders.GetOrCreate(ipKey, func() *OffenderRecord {
		return &OffenderRecord{
			OffenseCount: 1,
			FirstSeen:    now,
			LastOffense:  now,
			BanLevel:     1,
		}
	})

	rec := entry.Value
	if !isNew {
		rec.OffenseCount++
		rec.LastOffense = now
		if rec.OffenseCount >= 5 {
			rec.BanLevel = 4 // 24 Hours
		} else if rec.OffenseCount >= 3 {
			rec.BanLevel = 3 // 1 Hour
		} else if rec.OffenseCount >= 2 {
			rec.BanLevel = 2 // 5 Minutes
		}
	}

	switch rec.BanLevel {
	case 4:
		return 24 * time.Hour
	case 3:
		return 1 * time.Hour
	case 2:
		return 5 * time.Minute
	default:
		return 60 * time.Second
	}
}

// FormatAttackDiagnosis produces a human-friendly defense status summary.
func (ad *AutoDefense) FormatAttackDiagnosis() string {
	ad.mu.RLock()
	defer ad.mu.RUnlock()

	if ad.primaryVector == VectorNone {
		return "System Normal — No active DDoS vector detected"
	}
	return fmt.Sprintf("Active Attack Detected: %s (Mitigation: Auto-Throttled)", ad.primaryVector)
}
