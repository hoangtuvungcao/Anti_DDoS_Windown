package engine

import (
	"fmt"
	"net"
	"runtime"
	"sync"
	"time"

	"waf-game/pkg/logger"
	"waf-game/pkg/packet"
	"waf-game/pkg/stats"
	"waf-game/pkg/windivert"
)

const (
	GeoIPModeOff  = 0
	GeoIPModeOn   = 1
	GeoIPModeAuto = 2

	EntropyModeOff  = 0
	EntropyModeOn   = 1
	EntropyModeAuto = 2
)

// Engine is the core firewall processing pipeline.
// Coordinates all 5 layers + dynamic state management + AI AutoDefense.
type Engine struct {
	// WinDivert handles
	inboundHandle  *windivert.Handle
	outboundHandle *windivert.Handle

	// Layers
	ipFilter    *IPFilter      // Layer 0: Whitelist / Blacklist
	layer1      *Layer1Filter  // Layer 1: Garbage & Amplification
	discovery   *PortDiscovery // Layer 2: Port Discovery
	tcpShield   *TCPShield     // Layer 3: TCP Shield
	udpShield   *UDPShield     // Layer 4 & 4.5: UDP & Game Shield
	state       *StateManager
	geoIPMode   int
	entropyMode int
	modeManager *ModeManager
	geoIP       *GeoIP
	autoDefense *AutoDefense

	// Metrics
	metrics *stats.Metrics

	// Packet buffer memory pool for zero GC allocation
	bufPool sync.Pool

	// Control
	stopCh  chan struct{}
	wg      sync.WaitGroup
	workers int
	running bool

	// Logger
	fastLogger *logger.FastLogger
}

// EngineConfig holds engine configuration
type EngineConfig struct {
	Workers           int
	DiscoveryInterval time.Duration
	ExcludePorts      []uint16

	// Peace mode settings
	UDPFlowPPS                float64
	UDPFlowBPS                float64
	UDPPerIPPPS               float64
	SubnetPPS                 float64
	BlacklistDur              time.Duration
	TCPMaxConnIP              int32
	TCPConnRateIP             int32
	TCPMaxConnSubnet          int32
	TCPIdleTimeout            int64
	EnableAmplificationFilter bool
	EnableGameShield          bool

	// War mode settings
	WarTriggerPPS uint64
	WarTriggerBPS uint64
	WarCooldown   int64
	WarFlowPPS    float64
	WarIPPPS      float64
	WarSubnetPPS  float64

	// Features
	EntropyMode  int
	TwoWayVerify bool
	GeoIPMode    int
	SystemMode   string

	// Lists & Rules
	WhitelistIPs []string
	BlacklistIPs []string
	GameRules    []CustomGameRule

	// FastLogger
	FastLogger *logger.FastLogger
}

// DefaultConfig returns sensible defaults for high performance
func DefaultConfig() EngineConfig {
	return EngineConfig{
		Workers:                   0, // Auto CPU
		DiscoveryInterval:         5 * time.Second,
		UDPFlowPPS:                150,
		UDPFlowBPS:                2097152, // 2 MB/s
		UDPPerIPPPS:               500,
		SubnetPPS:                 1500,
		BlacklistDur:              5 * time.Minute,
		TCPMaxConnIP:              100,
		TCPConnRateIP:             30,
		TCPMaxConnSubnet:          500,
		TCPIdleTimeout:            120,
		EnableAmplificationFilter: true,
		EnableGameShield:          true,
		WarTriggerPPS:             5000,
		WarTriggerBPS:             52428800, // 50 MB/s
		WarCooldown:               60,
		WarFlowPPS:                40,
		WarIPPPS:                  100,
		WarSubnetPPS:              250,
		EntropyMode:               EntropyModeAuto,
		GeoIPMode:                 GeoIPModeAuto,
		SystemMode:                "AUTO",
		WhitelistIPs:              []string{"127.0.0.1"},
	}
}


// NewEngine creates a new firewall engine.
func NewEngine(cfg EngineConfig, metrics *stats.Metrics, fastLog *logger.FastLogger) (*Engine, error) {
	inHandle, err := windivert.Open(
		"inbound and (fragment or tcp or udp or icmp or ip)",
		windivert.LayerNetwork,
		0, // priority
		windivert.FlagDefault,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to open inbound WinDivert handle: %w", err)
	}

	// Set high-performance queue parameters for burst tolerance
	inHandle.SetParam(windivert.ParamQueueLen, 65536)     // 64k packets
	inHandle.SetParam(windivert.ParamQueueTime, 2000)     // 2 seconds
	inHandle.SetParam(windivert.ParamQueueSize, 67108864) // 64 MB

	outHandle, err := windivert.Open(
		"outbound and (tcp or udp or icmp)",
		windivert.LayerNetwork,
		-1,                  // lower priority
		windivert.FlagSniff, // sniff only — don't capture outbound
	)
	if err != nil {
		inHandle.Close()
		return nil, fmt.Errorf("failed to open outbound WinDivert handle: %w", err)
	}


	workers := cfg.Workers
	if workers <= 0 {
		workers = runtime.NumCPU()
		if workers < 2 {
			workers = 2
		} else if workers > 16 {
			workers = 16
		}
	}

	ipFilter := NewIPFilter(cfg.WhitelistIPs, cfg.BlacklistIPs)
	layer1 := NewLayer1Filter()
	layer1.SetAmplificationFilter(cfg.EnableAmplificationFilter)

	discovery := NewPortDiscovery(cfg.DiscoveryInterval, cfg.ExcludePorts)
	tcpShield := NewTCPShield(inHandle, cfg.TCPMaxConnIP, cfg.TCPConnRateIP, cfg.TCPMaxConnSubnet, cfg.TCPIdleTimeout)
	udpShield := NewUDPShield(cfg.UDPFlowPPS, cfg.UDPFlowBPS, cfg.UDPPerIPPPS, cfg.SubnetPPS, cfg.BlacklistDur, cfg.GameRules)
	udpShield.Discovery = discovery
	if udpShield.GameShield != nil {
		udpShield.GameShield.SetEnabled(cfg.EnableGameShield)
	}

	stateManager := NewStateManager(cfg.WarTriggerPPS, cfg.WarTriggerBPS, cfg.WarCooldown)
	geoIP := NewGeoIP(fastLog)
	autoDefense := NewAutoDefense(metrics, fastLog)

	initialEntropy := false
	if cfg.EntropyMode == EntropyModeOn {
		initialEntropy = true
	}
	udpShield.SetEntropy(initialEntropy)

	engine := &Engine{
		inboundHandle:  inHandle,
		outboundHandle: outHandle,
		ipFilter:       ipFilter,
		layer1:         layer1,
		discovery:      discovery,
		tcpShield:      tcpShield,
		udpShield:      udpShield,
		state:          stateManager,
		geoIP:          geoIP,
		autoDefense:    autoDefense,
		geoIPMode:      cfg.GeoIPMode,
		entropyMode:    cfg.EntropyMode,
		metrics:        metrics,
		bufPool: sync.Pool{
			New: func() interface{} {
				b := make([]byte, 65535)
				return &b
			},
		},
		stopCh:     make(chan struct{}),
		workers:    workers,
		running:    false,
		fastLogger: fastLog,
	}

	engine.modeManager = NewModeManager(cfg.SystemMode, stateManager, engine)

	stateManager.SetCallbacks(
		func() { // On War Mode
			if fastLog != nil {
				fastLog.Warn("WAR_MODE", "Escalated to WAR MODE — activating strict limits, DPI & Geo-Shield")
			}
			engine.modeManager.applyMode(true)
		},
		func() { // On Peace Mode
			if fastLog != nil {
				fastLog.Info("PEACE_MODE", "Restored to PEACE MODE — normal network conditions")
			}
			engine.modeManager.applyMode(false)
		},
	)

	return engine, nil
}

// Start begins packet processing with N worker goroutines.
func (e *Engine) Start() {
	e.running = true

	e.discovery.Start()

	for i := 0; i < e.workers; i++ {
		e.wg.Add(1)
		go e.worker(i)
	}

	e.wg.Add(1)
	go e.outboundTracker()

	e.wg.Add(1)
	go e.sweeper()

	e.wg.Add(1)
	go e.stateEvaluator()

	if e.fastLogger != nil {
		e.fastLogger.Info("ENGINE", "Started with %d parallel packet workers (Memory Pool Active)", e.workers)
	}
}

// Stop gracefully shuts down the engine.
func (e *Engine) Stop() {
	if !e.running {
		return
	}
	e.running = false

	close(e.stopCh)
	e.discovery.Stop()

	e.inboundHandle.Close()
	e.outboundHandle.Close()

	e.wg.Wait()
	if e.fastLogger != nil {
		e.fastLogger.Info("ENGINE", "Firewall engine stopped cleanly")
	}
}

// worker processes inbound packets using zero-allocation buffer pool.
func (e *Engine) worker(id int) {
	defer e.wg.Done()

	bufPtr := e.bufPool.Get().(*[]byte)
	defer e.bufPool.Put(bufPtr)
	buf := *bufPtr

	var addr windivert.Address
	var pkt packet.Packet

	for {
		select {
		case <-e.stopCh:
			return
		default:
		}

		n, err := e.inboundHandle.Recv(buf, &addr)
		if err != nil {
			select {
			case <-e.stopCh:
				return
			default:
				continue
			}
		}

		if n == 0 {
			continue
		}

		if err := packet.Parse(buf[:n], &pkt); err != nil {
			continue
		}

		// ═══ LAYER 0: Whitelist & Blacklist (Fast Path) ═══
		action := e.ipFilter.Check(pkt.SrcIP)
		if action == ActionWhitelist {
			e.metrics.WhitelistHits.Add(1)
			e.inboundHandle.Send(buf[:n], &addr)
			continue
		} else if action == ActionBlacklist {
			e.metrics.Layer0Drops.Add(1)
			e.metrics.DroppedPPS.Add(1)
			e.metrics.DroppedBPS.Add(uint64(pkt.TotalLen))
			continue
		}

		// ═══ GEOIP COUNTRY FILTER (O(log N) Binary Search) ═══
		shouldGeoBlock := false
		if e.geoIPMode == GeoIPModeOn {
			shouldGeoBlock = true
		} else if e.geoIPMode == GeoIPModeAuto && e.state.IsWarMode() {
			shouldGeoBlock = true
		}

		if shouldGeoBlock {
			srcIP := net.IP(pkt.SrcIP[:])
			if !e.geoIP.IsVietnamIP(srcIP) {

				isResponse := false
				if pkt.Protocol == packet.ProtoTCP {
					if !pkt.IsSYN() {
						isResponse = true
					}
				} else if pkt.Protocol == packet.ProtoUDP {
					isResponse = e.udpShield.verifyTwoWay(&pkt)
				}

				if !isResponse {
					e.metrics.Layer1Drops.Add(1)
					e.metrics.DroppedPPS.Add(1)
					continue
				}
			}
		}

		// Record traffic volume
		e.state.RecordPacket(pkt.TotalLen)
		e.metrics.InboundPPS.Add(1)
		e.metrics.InboundBPS.Add(uint64(pkt.TotalLen))

		// ═══ LAYER 1: Global Garbage & Reflection Filter ═══
		result, rule := e.layer1.Check(&pkt)
		if result == FilterDrop {
			e.metrics.Layer1Drops.Add(1)
			e.metrics.DroppedPPS.Add(1)
			e.metrics.DroppedBPS.Add(uint64(pkt.TotalLen))
			_ = rule
			continue
		}

		// Drop UDP Amplification / Reflection Floods
		if pkt.Protocol == packet.ProtoUDP && e.layer1.IsReflectionPort(pkt.SrcPort) {
			if !e.udpShield.verifyTwoWay(&pkt) {
				e.metrics.ReflectionDrops.Add(1)
				e.metrics.DroppedPPS.Add(1)
				e.metrics.DroppedBPS.Add(uint64(pkt.TotalLen))
				continue
			}
		}

		// ═══ LAYER 3 & 4: Protocol-specific Shields ═══
		isTCP := pkt.Protocol == packet.ProtoTCP

		if isTCP {
			result := e.tcpShield.ProcessTCP(&pkt, buf[:n], &addr)
			if result == FilterDrop {
				e.metrics.Layer3Drops.Add(1)
				e.metrics.DroppedPPS.Add(1)
				e.metrics.DroppedBPS.Add(uint64(pkt.TotalLen))
				continue
			}
		} else if pkt.Protocol == packet.ProtoUDP {
			result := e.udpShield.ProcessUDP(&pkt, buf[:n])
			if result == FilterDrop {
				e.metrics.Layer4Drops.Add(1)
				e.metrics.DroppedPPS.Add(1)
				e.metrics.DroppedBPS.Add(uint64(pkt.TotalLen))
				continue
			}
		}

		// ═══ PASS — Reinject packet into network stack ═══
		e.inboundHandle.Send(buf[:n], &addr)
	}
}


// outboundTracker monitors outbound UDP & TCP packets for two-way verification
func (e *Engine) outboundTracker() {
	defer e.wg.Done()

	buf := make([]byte, 65535)
	var addr windivert.Address
	var pkt packet.Packet

	for {
		select {
		case <-e.stopCh:
			return
		default:
		}

		n, err := e.outboundHandle.Recv(buf, &addr)
		if err != nil {
			select {
			case <-e.stopCh:
				return
			default:
				continue
			}
		}

		if n == 0 {
			continue
		}

		if err := packet.Parse(buf[:n], &pkt); err != nil {
			continue
		}


		// Record outbound traffic volume & two-way verification
		e.metrics.OutboundPPS.Add(1)
		e.metrics.OutboundBPS.Add(uint64(n))

		if pkt.Protocol == packet.ProtoUDP {
			e.udpShield.TrackOutbound(pkt.DstIP, pkt.DstPort)
		} else if pkt.Protocol == packet.ProtoTCP && pkt.IsSYN() {
			e.tcpShield.TrackOutbound(pkt.DstIP, pkt.DstPort, pkt.SrcPort)
		}
	}
}



// sweeper periodically cleans up expired state entries and dead connections
func (e *Engine) sweeper() {
	defer e.wg.Done()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	tcpReapTicker := time.NewTicker(2 * time.Second)
	defer tcpReapTicker.Stop()

	for {
		select {
		case <-ticker.C:
			e.udpShield.SweepFlows(30 * time.Second)

		case <-tcpReapTicker.C:
			e.tcpShield.ReapIdleConnections()
			e.tcpShield.ReapHalfOpenAndZeroPayload()

		case <-e.stopCh:
			return
		}
	}
}

// stateEvaluator checks traffic levels every second for mode switching and AI baseline adaptation
func (e *Engine) stateEvaluator() {
	defer e.wg.Done()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			e.state.Evaluate()

			mode := int32(e.state.GetMode())
			e.metrics.CurrentMode.Store(mode)
			e.metrics.ThreatLevel.Store(mode)
			e.metrics.ActiveFlows.Store(uint64(e.udpShield.GetFlowCount()))
			e.metrics.VerifiedTCP.Store(uint64(e.tcpShield.GetVerifiedCount()))
			e.metrics.BlacklistedIPs.Store(uint64(e.udpShield.GetBlacklistedCount()))

			// Adapt AI defense baseline
			if e.autoDefense != nil {
				e.autoDefense.EvaluateBaselineAndUpdate(e.state.IsWarMode())
			}

		case <-e.stopCh:
			return
		}
	}
}

// GetAutoDefense returns the AI heuristics and attack classifier module.
func (e *Engine) GetAutoDefense() *AutoDefense {
	return e.autoDefense
}

// GetFastLogger returns the asynchronous ring-buffer fast logger.
func (e *Engine) GetFastLogger() *logger.FastLogger {
	return e.fastLogger
}

// GetIPFilter returns the Layer 0 IP filter.
func (e *Engine) GetIPFilter() *IPFilter {
	return e.ipFilter
}

// GetDiscovery returns the port discovery module for CLI display.
func (e *Engine) GetDiscovery() *PortDiscovery {
	return e.discovery
}

// GetState returns the state manager for CLI display.
func (e *Engine) GetState() *StateManager {
	return e.state
}

// GetUDPShield returns the UDP shield for stats display.
func (e *Engine) GetUDPShield() *UDPShield {
	return e.udpShield
}

// GetTCPShield returns the TCP shield for stats and configuration.
func (e *Engine) GetTCPShield() *TCPShield {
	return e.tcpShield
}

// GetModeManager returns the centralized mode manager.
func (e *Engine) GetModeManager() *ModeManager {
	return e.modeManager
}

// GetGeoIPMode returns the current GeoIP mode.
func (e *Engine) GetGeoIPMode() int {
	return e.geoIPMode
}

// SetGeoIPMode sets the GeoIP mode.
func (e *Engine) SetGeoIPMode(mode int) {
	e.geoIPMode = mode
}

// GetEntropyMode returns the current UDP Entropy mode.
func (e *Engine) GetEntropyMode() int {
	return e.entropyMode
}

// SetEntropyMode sets the UDP Entropy mode and updates the shield state.
func (e *Engine) SetEntropyMode(mode int) {
	e.entropyMode = mode
	shouldEntropy := false
	if mode == EntropyModeOn {
		shouldEntropy = true
	} else if mode == EntropyModeAuto && e.state.IsWarMode() {
		shouldEntropy = true
	}
	e.udpShield.SetEntropy(shouldEntropy)
}


