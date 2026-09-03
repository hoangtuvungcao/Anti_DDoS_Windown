package engine

import (
	"fmt"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
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
	cfg   EngineConfig
	cfgMu sync.RWMutex

	// WinDivert handles
	inboundHandle  *windivert.Handle
	outboundHandle *windivert.Handle

	// Layers
	ipFilter            *IPFilter      // Layer 0: Whitelist / Blacklist
	layer1              *Layer1Filter  // Layer 1: Garbage & Amplification
	discovery           *PortDiscovery // Layer 2: Port Discovery
	tcpShield           *TCPShield     // Layer 3: TCP Shield
	udpShield           *UDPShield     // Layer 4 & 4.5: UDP & Game Shield
	state               *StateManager
	geoIPMode           atomic.Int32
	entropyMode         atomic.Int32
	advancedEnforcement atomic.Bool
	strictWhitelist     bool
	modeManager         *ModeManager
	geoIP               *GeoIP
	autoDefense         *AutoDefense

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
	fastLogger     *logger.FastLogger
	attackCallback func(active bool, vector string, pps, bps, drops uint64)
}

// EngineConfig holds engine configuration
type EngineConfig struct {
	Workers            int
	DiscoveryInterval  time.Duration
	ExcludePorts       []uint16
	CacheMaxEntries    int
	CacheTTL           time.Duration
	CacheSweepInterval time.Duration

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
	EnableDPIShield           bool
	PeaceMonitorOnly          bool

	// War mode settings
	WarTriggerPPS uint64
	WarTriggerBPS uint64
	WarCooldown   int64
	WarFlowPPS    float64
	WarIPPPS      float64
	WarSubnetPPS  float64
	WarFlowBPS    float64
	WarEnableDPI  bool

	// Features
	EntropyMode     int
	TwoWayVerify    bool
	GeoIPMode       int
	SystemMode      string
	StrictWhitelist bool

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
		CacheMaxEntries:           300000,
		CacheTTL:                  30 * time.Second,
		CacheSweepInterval:        10 * time.Second,
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
		EnableDPIShield:           true,
		PeaceMonitorOnly:          true,
		WarTriggerPPS:             5000,
		WarTriggerBPS:             52428800, // 50 MB/s
		WarCooldown:               60,
		WarFlowPPS:                40,
		WarFlowBPS:                524288,
		WarIPPPS:                  100,
		WarSubnetPPS:              250,
		WarEnableDPI:              true,
		EntropyMode:               EntropyModeAuto,
		TwoWayVerify:              true,
		GeoIPMode:                 GeoIPModeAuto,
		SystemMode:                "AUTO",
		StrictWhitelist:           true,
		WhitelistIPs:              []string{"127.0.0.1"},
	}
}

// NewEngine creates a new firewall engine.
func NewEngine(cfg EngineConfig, metrics *stats.Metrics, fastLog *logger.FastLogger) (*Engine, error) {
	inHandle, err := windivert.Open(
		"inbound and !loopback and (fragment or tcp or udp or icmp or ip)",
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
		"outbound and !loopback and (tcp or udp or icmp)",
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
		cfg:            cfg,
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
		metrics:        metrics,
		bufPool: sync.Pool{
			New: func() interface{} {
				b := make([]byte, 65535)
				return &b
			},
		},
		stopCh:          make(chan struct{}),
		workers:         workers,
		running:         false,
		fastLogger:      fastLog,
		strictWhitelist: cfg.StrictWhitelist,
	}
	engine.geoIPMode.Store(int32(cfg.GeoIPMode))
	engine.entropyMode.Store(int32(cfg.EntropyMode))

	engine.modeManager = NewModeManager(cfg.SystemMode, stateManager, engine)

	stateManager.SetCallbacks(
		func() { // On War Mode
			if fastLog != nil {
				fastLog.Warn("WAR_MODE", "Escalated to WAR MODE — activating strict limits, DPI & Geo-Shield")
			}
			engine.modeManager.applyMode(true)
			if engine.attackCallback != nil {
				vector := "GENERIC FLOOD"
				if engine.state.IsBotnetDetected() {
					vector = string(VectorSubnetBotnet)
				}
				engine.attackCallback(true, vector, engine.state.GetCurrentPPS(), engine.state.GetCurrentBPS(), engine.metrics.DroppedPPS.Load())
			}
		},
		func() { // On Peace Mode
			if fastLog != nil {
				fastLog.Info("PEACE_MODE", "Restored to PEACE MODE — normal network conditions")
			}
			engine.modeManager.applyMode(false)
			if engine.attackCallback != nil {
				engine.attackCallback(false, string(engine.autoDefense.GetPrimaryAttackVector()), engine.state.GetCurrentPPS(), engine.state.GetCurrentBPS(), engine.metrics.DroppedPPS.Load())
			}
		},
	)

	return engine, nil
}

// SetAttackCallback registers a non-blocking incident callback before Start.
func (e *Engine) SetAttackCallback(callback func(active bool, vector string, pps, bps, drops uint64)) {
	e.attackCallback = callback
}

// ConfigurePeaceUDP persists a dashboard preset across War/Peace transitions.
func (e *Engine) ConfigurePeaceUDP(flowPPS, flowBPS, ipPPS, subnetPPS float64, dpi, game bool) {
	e.cfgMu.Lock()
	e.cfg.UDPFlowPPS = flowPPS
	e.cfg.UDPFlowBPS = flowBPS
	e.cfg.UDPPerIPPPS = ipPPS
	e.cfg.SubnetPPS = subnetPPS
	e.cfg.EnableDPIShield = dpi
	e.cfg.EnableGameShield = game
	e.cfgMu.Unlock()
}

func (e *Engine) IsAdvancedEnforcementEnabled() bool {
	return e.advancedEnforcement.Load()
}

// Start begins packet processing with N worker goroutines.
func (e *Engine) Start() {
	e.running = true
	e.modeManager.ApplyCurrent()

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

		// Feed telemetry before fast-path decisions so blocked bot traffic still
		// contributes to attack detection and dashboard input counters.
		suspiciousSource := pkt.IsSYN()
		if pkt.Protocol == packet.ProtoUDP {
			suspiciousSource = !e.udpShield.verifyTwoWay(&pkt)
		}
		e.state.RecordPacketDetails(pkt.TotalLen, pkt.SrcIPUint32(), pkt.Protocol, pkt.IsSYN(), suspiciousSource)
		e.metrics.InboundPPS.Add(1)
		e.metrics.InboundBPS.Add(uint64(pkt.TotalLen))

		// ═══ LAYER 0: Whitelist & Blacklist (Fast Path) ═══
		action := e.ipFilter.Check(pkt.SrcIP)
		if action == ActionWhitelist {
			e.metrics.WhitelistHits.Add(1)
			if e.strictWhitelist {
				e.inboundHandle.Send(buf[:n], &addr)
				continue
			}
		} else if action == ActionBlacklist {
			e.metrics.Layer0Drops.Add(1)
			e.metrics.DroppedPPS.Add(1)
			e.metrics.DroppedBPS.Add(uint64(pkt.TotalLen))
			continue
		}

		// Explicit operator exclusions bypass all heuristic/Geo/rate filters while
		// static blacklist rules above still take precedence.
		if e.discovery.IsExcluded(pkt.DstPort) {
			e.inboundHandle.Send(buf[:n], &addr)
			continue
		}
		// Adopt only connections that Windows itself reports as ESTABLISHED. This
		// preserves sessions opened before the shield without any port-based bypass.
		if pkt.Protocol == packet.ProtoTCP && pkt.IsACK() && e.discovery.IsEstablishedTCP(pkt.ConnKey()) {
			e.tcpShield.ObserveTCP(&pkt, true)
		}

		// ═══ GEOIP COUNTRY FILTER (O(log N) Binary Search) ═══
		geoMode := int(e.geoIPMode.Load()) // load once
		shouldGeoBlock := geoMode == GeoIPModeOn || (geoMode == GeoIPModeAuto && e.state.IsWarMode())

		if shouldGeoBlock {
			srcIP := net.IP(pkt.SrcIP[:])
			if !e.geoIP.IsVietnamIP(srcIP) {
				isResponse := false
				if pkt.Protocol == packet.ProtoTCP {
					// Bug fix: previously used '!pkt.IsSYN()' which allowed foreign ACK/RST/FIN floods to bypass GeoIP!
					// Now strictly checks if connection was verified (outbound response or established session).
					isResponse = e.tcpShield.IsVerified(pkt.ConnKey())
				} else if pkt.Protocol == packet.ProtoUDP {
					isResponse = e.udpShield.verifyTwoWay(&pkt)
				}

				if !isResponse {
					e.metrics.Layer1Drops.Add(1)
					e.metrics.DroppedPPS.Add(1)
					e.metrics.DroppedBPS.Add(uint64(pkt.TotalLen)) // Bug fix: missing BPS counter
					continue
				}
			}
		}

		// ═══ LAYER 1: Global Garbage & Reflection Filter ═══
		result, rule := e.layer1.Check(&pkt)
		if result == FilterDrop {
			e.metrics.Layer1Drops.Add(1)
			e.metrics.DroppedPPS.Add(1)
			e.metrics.DroppedBPS.Add(uint64(pkt.TotalLen))
			_ = rule
			continue
		}

		// Peace/Elevated monitor-only mode preserves game discovery, RCON,
		// third-party control panels, VoIP and remote administration traffic.
		if !e.advancedEnforcement.Load() {
			if pkt.Protocol == packet.ProtoTCP {
				e.tcpShield.ObserveTCP(&pkt, e.discovery.IsEstablishedTCP(pkt.ConnKey()))
			}
			e.inboundHandle.Send(buf[:n], &addr)
			continue
		}

		// ═══ LAYER 2: Socket Discovery (Closed Port Scan & Attack Filter) ═══
		if pkt.Protocol == packet.ProtoTCP {
			// Only drop unsolicited SYN packets targeting closed ports.
			// NEVER drop response packets (SYN-ACK, ACK, Data) for outbound connections (UltraViewer, IslePilot, HTTPS)!
			if pkt.IsSYN() && !pkt.IsSYNACK() {
				if !e.discovery.IsListening(pkt.DstPort, true) {
					e.metrics.Layer2Drops.Add(1)
					e.metrics.DroppedPPS.Add(1)
					e.metrics.DroppedBPS.Add(uint64(pkt.TotalLen))
					continue
				}
			}
		} else if pkt.Protocol == packet.ProtoUDP {
			// For UDP: Only drop if port is closed, not a two-way response, and not DNS response
			if !e.discovery.IsListening(pkt.DstPort, false) && !e.udpShield.verifyTwoWay(&pkt) && pkt.SrcPort != 53 {
				e.metrics.Layer2Drops.Add(1)
				e.metrics.DroppedPPS.Add(1)
				e.metrics.DroppedBPS.Add(uint64(pkt.TotalLen))
				continue
			}
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
				if !pkt.IsSYN() {
					e.metrics.OutOfStateDrops.Add(1)
				}
				e.metrics.DroppedPPS.Add(1)
				e.metrics.DroppedBPS.Add(uint64(pkt.TotalLen))
				continue
			}
		} else if pkt.Protocol == packet.ProtoUDP {
			result, reason := e.udpShield.ProcessUDPWithReason(&pkt, buf[:n])
			if result == FilterDrop {
				e.metrics.Layer4Drops.Add(1)
				switch reason {
				case DropSubnetRate:
					e.metrics.SubnetDrops.Add(1)
				case DropGameQuery, DropDPI:
					e.metrics.GameQueryDrops.Add(1)
				case DropEntropy:
					e.metrics.EntropyDrops.Add(1)
				case DropUnverified:
					e.metrics.UnverifiedDrops.Add(1)
				}
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

	e.cfgMu.RLock()
	sweepInterval, cacheTTL, cacheMaxEntries := e.cfg.CacheSweepInterval, e.cfg.CacheTTL, e.cfg.CacheMaxEntries
	e.cfgMu.RUnlock()
	if sweepInterval <= 0 {
		sweepInterval = 10 * time.Second
	}
	if cacheTTL <= 0 {
		cacheTTL = 30 * time.Second
	}
	if cacheMaxEntries <= 0 {
		cacheMaxEntries = 300000
	}
	ticker := time.NewTicker(sweepInterval)
	defer ticker.Stop()

	tcpReapTicker := time.NewTicker(2 * time.Second)
	defer tcpReapTicker.Stop()

	slowlorisTicker := time.NewTicker(10 * time.Second) // Slowloris detection needs 15s threshold
	defer slowlorisTicker.Stop()

	for {
		select {
		case <-ticker.C:
			e.udpShield.SweepFlows(cacheTTL)
			e.udpShield.EnforceCapacity(cacheMaxEntries)
			e.tcpShield.EnforceCapacity(cacheMaxEntries)

		case <-tcpReapTicker.C:
			e.tcpShield.ReapIdleConnections()
			e.tcpShield.ReapHalfOpenAndZeroPayload()

		case <-slowlorisTicker.C:
			// Bug fix: ReapSlowlorisConnections was never called — Slowloris attacks could hold connections forever
			e.tcpShield.ReapSlowlorisConnections()

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
			e.metrics.Snapshot()

			mode := int32(e.state.GetMode())
			e.metrics.CurrentMode.Store(mode)
			e.metrics.ThreatLevel.Store(mode)
			e.metrics.ActiveFlows.Store(uint64(e.udpShield.GetFlowCount()))
			e.metrics.VerifiedTCP.Store(uint64(e.tcpShield.GetVerifiedCount()))
			e.metrics.BlacklistedIPs.Store(uint64(e.udpShield.GetBlacklistedCount()))
			e.metrics.UniqueSourceIPs.Store(e.state.GetUniqueIPs())
			e.metrics.UniqueSubnets.Store(e.state.GetUniqueSubnets())
			e.metrics.BotnetDetected.Store(e.state.IsBotnetDetected())

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
	return int(e.geoIPMode.Load())
}

// SetGeoIPMode sets the GeoIP mode.
func (e *Engine) SetGeoIPMode(mode int) {
	e.geoIPMode.Store(int32(mode))
}

// GetEntropyMode returns the current UDP Entropy mode.
func (e *Engine) GetEntropyMode() int {
	return int(e.entropyMode.Load())
}

// SetEntropyMode sets the UDP Entropy mode and updates the shield state.
func (e *Engine) SetEntropyMode(mode int) {
	e.entropyMode.Store(int32(mode))
	shouldEntropy := false
	if mode == EntropyModeOn {
		shouldEntropy = true
	} else if mode == EntropyModeAuto && e.state.IsWarMode() {
		shouldEntropy = true
	}
	e.udpShield.SetEntropy(shouldEntropy)
}
