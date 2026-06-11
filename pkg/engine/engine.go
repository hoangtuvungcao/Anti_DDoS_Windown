package engine

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

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
// Coordinates all 4 layers + dynamic state management.
type Engine struct {
	// WinDivert handles
	inboundHandle  *windivert.Handle
	outboundHandle *windivert.Handle

	// Layers
	layer1    *Layer1Filter
	discovery *PortDiscovery
	tcpShield *TCPShield
	udpShield *UDPShield
	state     *StateManager
	geoIPMode int
	entropyMode int
	modeManager *ModeManager
	geoIP     *GeoIP

	// Metrics
	metrics *stats.Metrics

	// Control
	stopCh    chan struct{}
	wg        sync.WaitGroup
	workers   int
	running   bool

	// Logger
	logger *log.Logger
}

// EngineConfig holds engine configuration
type EngineConfig struct {
	Workers          int
	DiscoveryInterval time.Duration
	ExcludePorts     []uint16

	// Peace mode settings
	UDPFlowPPS    float64
	UDPFlowBPS    float64
	UDPPerIPPPS   float64
	BlacklistDur  time.Duration
	TCPMaxConnIP  int32
	TCPIdleTimeout int64

	// War mode settings
	WarTriggerPPS uint64
	WarTriggerBPS uint64
	WarCooldown   int64
	WarFlowPPS    float64

	// Features
	EntropyMode   int
	TwoWayVerify  bool
	GeoIPMode     int
	SystemMode    string
}

// DefaultConfig returns sensible defaults for 2-core / 8GB RAM systems
func DefaultConfig() EngineConfig {
	return EngineConfig{
		Workers:           2,
		DiscoveryInterval: 5 * time.Second,
		UDPFlowPPS:        150,
		UDPFlowBPS:        1048576, // 1 MB/s
		UDPPerIPPPS:       500,
		BlacklistDur:      5 * time.Minute,
		TCPMaxConnIP:      100,
		TCPIdleTimeout:    5,
		WarTriggerPPS:     50000,
		WarTriggerBPS:     209715200, // 200 MB/s
		WarCooldown:       60,
		WarFlowPPS:        100,
	}
}

// NewEngine creates a new firewall engine.
func NewEngine(cfg EngineConfig, metrics *stats.Metrics, logger *log.Logger) (*Engine, error) {
	// Open inbound WinDivert handle — captures ALL inbound TCP/UDP/fragments
	inHandle, err := windivert.Open(
		"inbound and (fragment or tcp or udp)",
		windivert.LayerNetwork,
		0, // priority
		windivert.FlagDefault,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to open inbound WinDivert handle: %w", err)
	}

	// Set queue parameters for high throughput
	inHandle.SetParam(windivert.ParamQueueLen, 16384)
	inHandle.SetParam(windivert.ParamQueueTime, 2000) // 2 seconds
	inHandle.SetParam(windivert.ParamQueueSize, 33554432) // 32 MB

	// Open outbound handle for two-way verification (both TCP and UDP)
	outHandle, err := windivert.Open(
		"outbound and (tcp or udp)",
		windivert.LayerNetwork,
		-1, // lower priority
		windivert.FlagSniff, // sniff only — don't capture outbound
	)
	if err != nil {
		inHandle.Close()
		return nil, fmt.Errorf("failed to open outbound WinDivert handle: %w", err)
	}

	// Initialize all layers
	layer1 := NewLayer1Filter()
	discovery := NewPortDiscovery(cfg.DiscoveryInterval, cfg.ExcludePorts)
	tcpShield := NewTCPShield(inHandle, cfg.TCPMaxConnIP, cfg.TCPIdleTimeout)
	udpShield := NewUDPShield(cfg.UDPFlowPPS, cfg.UDPFlowBPS, cfg.UDPPerIPPPS, cfg.BlacklistDur)
	udpShield.Discovery = discovery
	stateManager := NewStateManager(cfg.WarTriggerPPS, cfg.WarTriggerBPS, cfg.WarCooldown)
	geoIP := NewGeoIP(logger)

	initialEntropy := false
	if cfg.EntropyMode == EntropyModeOn {
		initialEntropy = true
	}
	udpShield.SetEntropy(initialEntropy)

	engine := &Engine{
		inboundHandle:  inHandle,
		outboundHandle: outHandle,
		layer1:         layer1,
		discovery:      discovery,
		tcpShield:      tcpShield,
		udpShield:      udpShield,
		state:          stateManager,
		geoIP:          geoIP,
		geoIPMode:      cfg.GeoIPMode,
		entropyMode:    cfg.EntropyMode,
		metrics:        metrics,
		stopCh:         make(chan struct{}),
		workers:        cfg.Workers,
		running:        false,
		logger:         logger,
	}

	engine.modeManager = NewModeManager(cfg.SystemMode, stateManager, engine)

	// Set up War Mode transitions — delegate to ModeManager for consistent behavior
	stateManager.SetCallbacks(
		func() { // On War Mode
			logger.Println("[WAR MODE] Activated — enabling DPI, entropy check, strict limits, GeoIP & TCP SYN Cookies")
			engine.modeManager.applyMode(true)
		},
		func() { // On Peace Mode
			logger.Println("[PEACE MODE] Restored — normal operation")
			engine.modeManager.applyMode(false)
		},
	)

	return engine, nil
}

// Start begins packet processing with N worker goroutines.
func (e *Engine) Start() {
	e.running = true

	// Start port discovery scanner
	e.discovery.Start()

	// Start inbound workers
	for i := 0; i < e.workers; i++ {
		e.wg.Add(1)
		go e.worker(i)
	}

	// Start outbound tracker
	e.wg.Add(1)
	go e.outboundTracker()

	// Start sweeper
	e.wg.Add(1)
	go e.sweeper()

	// Start state evaluator
	e.wg.Add(1)
	go e.stateEvaluator()

	e.logger.Printf("[ENGINE] Started with %d workers", e.workers)
}

// Stop gracefully shuts down the engine.
func (e *Engine) Stop() {
	if !e.running {
		return
	}
	e.running = false

	close(e.stopCh)
	e.discovery.Stop()

	// Close handles — this will unblock any Recv calls
	e.inboundHandle.Close()
	e.outboundHandle.Close()

	e.wg.Wait()
	e.logger.Println("[ENGINE] Stopped gracefully")
}

// worker processes inbound packets through the 4-layer pipeline
func (e *Engine) worker(id int) {
	defer e.wg.Done()

	// Pre-allocate reusable buffers
	buf := make([]byte, 65535) // Max IP packet size
	var addr windivert.Address
	var pkt packet.Packet

	for {
		select {
		case <-e.stopCh:
			return
		default:
		}

		// Receive packet from WinDivert
		n, err := e.inboundHandle.Recv(buf, &addr)
		if err != nil {
			select {
			case <-e.stopCh:
				return // Normal shutdown
			default:
				continue
			}
		}

		if n == 0 {
			continue
		}

		// Parse packet headers
		if err := packet.Parse(buf[:n], &pkt); err != nil {
			continue // Unparseable — skip
		}

		// ═══ GEOIP COUNTRY FILTER ═══
		shouldGeoBlock := false
		if e.geoIPMode == GeoIPModeOn {
			shouldGeoBlock = true
		} else if e.geoIPMode == GeoIPModeAuto && e.state.IsWarMode() {
			shouldGeoBlock = true
		}

		if shouldGeoBlock {
			srcIP := net.IP(pkt.SrcIP[:])
			if !e.geoIP.IsVietnamIP(srcIP) {
				// Bypass Geo-IP block if this packet is a response to an outbound connection we initiated.
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
					continue // Drop unsolicited foreign IP
				}
			}
		}

		// Record for state manager
		e.state.RecordPacket(pkt.TotalLen)
		e.metrics.InboundPPS.Add(1)
		e.metrics.InboundBPS.Add(uint64(pkt.TotalLen))

		// ═══ LAYER 1: Global Garbage Filter ═══
		result, rule := e.layer1.Check(&pkt)
		if result == FilterDrop {
			e.metrics.Layer1Drops.Add(1)
			_ = rule
			continue // Drop — don't Send
		}

		// ═══ LAYER 2: Port Discovery Filter ═══
		isTCP := pkt.Protocol == packet.ProtoTCP
		if isTCP {
			// Only drop incoming connection attempts (SYN packets) to non-listening ports.
			// Established traffic or responses to outbound connections (SYN-ACK) should pass.
			if pkt.IsSYN() && !e.discovery.IsListening(pkt.DstPort, true) {
				e.metrics.Layer2Drops.Add(1)
				continue
			}
		} else if pkt.Protocol == packet.ProtoUDP {
			// Drop inbound UDP packets to non-listening ports unless they are responses
			// to outbound UDP requests we previously sent.
			if !e.discovery.IsListening(pkt.DstPort, false) && !e.udpShield.verifyTwoWay(&pkt) {
				e.metrics.Layer2Drops.Add(1)
				continue
			}
		}

		// ═══ LAYER 3 & 4: Protocol-specific processing ═══
		if isTCP {
			// TCP Shield — SYN Cookie + Idle Reaper
			result := e.tcpShield.ProcessTCP(&pkt, buf[:n], &addr)
			if result == FilterDrop {
				e.metrics.Layer3Drops.Add(1)
				e.metrics.DroppedPPS.Add(1)
				e.metrics.DroppedBPS.Add(uint64(pkt.TotalLen))
				continue
			}
		} else if pkt.Protocol == packet.ProtoUDP {
			// UDP Shield — Rate Limit + DPI + Entropy
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

// outboundTracker monitors outbound UDP packets for two-way verification
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

		// Record outbound UDP/TCP for two-way verification
		if pkt.Protocol == packet.ProtoUDP {
			e.udpShield.TrackOutbound(pkt.DstIP, pkt.DstPort)
		} else if pkt.Protocol == packet.ProtoTCP && pkt.IsSYN() {
			e.tcpShield.TrackOutbound(pkt.DstIP, pkt.DstPort, pkt.SrcPort)
		}

		// Sniff mode — packet is automatically reinjected by WinDivert
	}
}

// sweeper periodically cleans up expired state entries
func (e *Engine) sweeper() {
	defer e.wg.Done()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	tcpReapTicker := time.NewTicker(3 * time.Second)
	defer tcpReapTicker.Stop()

	for {
		select {
		case <-ticker.C:
			// Sweep expired flow/IP entries (TTL = 30 seconds)
			e.udpShield.SweepFlows(30 * time.Second)

		case <-tcpReapTicker.C:
			// Reap idle TCP connections
			e.tcpShield.ReapIdleConnections()

		case <-e.stopCh:
			return
		}
	}
}

// stateEvaluator checks traffic levels every second for mode switching
func (e *Engine) stateEvaluator() {
	defer e.wg.Done()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			e.state.Evaluate()

			// Update metrics
			if e.state.IsWarMode() {
				e.metrics.CurrentMode.Store(1)
			} else {
				e.metrics.CurrentMode.Store(0)
			}
			e.metrics.ActiveFlows.Store(uint64(e.udpShield.GetFlowCount()))
			e.metrics.VerifiedTCP.Store(uint64(e.tcpShield.GetVerifiedCount()))

		case <-e.stopCh:
			return
		}
	}
}

// GetDiscovery returns the port discovery module for CLI display
func (e *Engine) GetDiscovery() *PortDiscovery {
	return e.discovery
}

// GetState returns the state manager for CLI display
func (e *Engine) GetState() *StateManager {
	return e.state
}

// GetUDPShield returns the UDP shield for stats display
func (e *Engine) GetUDPShield() *UDPShield {
	return e.udpShield
}

// GetTCPShield returns the TCP shield for stats and configuration
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
