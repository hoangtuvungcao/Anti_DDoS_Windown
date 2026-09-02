//go:build windows

package cli

import (
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"waf-game/pkg/config"
	"waf-game/pkg/engine"
	"waf-game/pkg/logger"
	"waf-game/pkg/stats"
)

// ANSI escape codes (dynamically enabled only if OS console supports Virtual Terminal Processing)
var (
	clearScreen = "\033[2J\033[H"
	cursorHome  = "\033[H"
	clearLine   = "\033[K"
	bold        = "\033[1m"
	reset       = "\033[0m"
	red         = "\033[31m"
	green       = "\033[32m"
	yellow      = "\033[33m"
	blue        = "\033[34m"
	magenta     = "\033[35m"
	cyan        = "\033[36m"
	white       = "\033[37m"
	bgRed       = "\033[41m"
	bgGreen     = "\033[42m"
	bgYellow    = "\033[43m"
	bgBlue      = "\033[44m"
	bgMagenta   = "\033[45m"
	bgCyan      = "\033[46m"
	dim         = "\033[2m"

	supportsANSI = true
)

func init() {
	if runtime.GOOS == "windows" {
		supportsANSI = checkWindowsVT()
		if !supportsANSI {
			disableANSI()
		}
	}
}

func checkWindowsVT() bool {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	procGetStdHandle := kernel32.NewProc("GetStdHandle")
	procGetConsoleMode := kernel32.NewProc("GetConsoleMode")
	procSetConsoleMode := kernel32.NewProc("SetConsoleMode")

	const stdOutputHandle = uintptr(0xFFFFFFF5) // STD_OUTPUT_HANDLE = -11
	const enableVT = 0x0004

	hOut, _, _ := procGetStdHandle.Call(stdOutputHandle)
	if hOut == 0 || hOut == uintptr(syscall.InvalidHandle) {
		return false
	}

	var mode uint32
	r, _, _ := procGetConsoleMode.Call(hOut, uintptr(unsafe.Pointer(&mode)))
	if r == 0 {
		return false
	}

	// Try to enable Virtual Terminal Processing (Windows 10/Server 2016+)
	r, _, _ = procSetConsoleMode.Call(hOut, uintptr(mode|enableVT))
	return r != 0
}

func disableANSI() {
	clearScreen = ""
	cursorHome = ""
	clearLine = ""
	bold = ""
	reset = ""
	red = ""
	green = ""
	yellow = ""
	blue = ""
	magenta = ""
	cyan = ""
	white = ""
	bgRed = ""
	bgGreen = ""
	bgYellow = ""
	bgBlue = ""
	bgMagenta = ""
	bgCyan = ""
	dim = ""
}

func setCursorHome() {
	if supportsANSI {
		fmt.Print(cursorHome)
		return
	}
	if runtime.GOOS == "windows" {
		kernel32 := syscall.NewLazyDLL("kernel32.dll")
		procGetStdHandle := kernel32.NewProc("GetStdHandle")
		procSetConsoleCursorPosition := kernel32.NewProc("SetConsoleCursorPosition")

		hOut, _, _ := procGetStdHandle.Call(uintptr(0xFFFFFFF5))
		if hOut != 0 && hOut != uintptr(syscall.InvalidHandle) {
			procSetConsoleCursorPosition.Call(hOut, 0)
		}
	}
}

type ViewPage int

const (
	PageMain ViewPage = iota
	PageAttackRadar
	PageBlacklist
	PagePortInspector
	PageLogs
	PageSettings
	PageHelp
)

// Dashboard is the CLI terminal Cyber Security Control Center.
type Dashboard struct {
	metrics         *stats.Metrics
	eng             *engine.Engine
	cfg             *config.Config
	configPath      string
	startTime       time.Time
	stopCh          chan struct{}
	sigCh           chan<- os.Signal
	currentPage     ViewPage
	mu              sync.Mutex
	statusMsg       string
	statusMsgExpiry time.Time

	// Traffic history for Sparkline charts (last 20 seconds)
	ppsHistory     []uint64
	outPPSHistory  []uint64
	dropPPSHistory []uint64
	historyCap     int
}

// NewDashboard creates a new CLI dashboard.
func NewDashboard(metrics *stats.Metrics, eng *engine.Engine, sigCh chan<- os.Signal, cfg *config.Config, configPath string) *Dashboard {
	return &Dashboard{
		metrics:        metrics,
		eng:            eng,
		cfg:            cfg,
		configPath:     configPath,
		startTime:      time.Now(),
		stopCh:         make(chan struct{}),
		sigCh:          sigCh,
		currentPage:    PageMain,
		ppsHistory:     make([]uint64, 0, 20),
		outPPSHistory:  make([]uint64, 0, 20),
		dropPPSHistory: make([]uint64, 0, 20),
		historyCap:     20,
	}
}

// Start begins the dashboard refresh loop.
func (d *Dashboard) Start() {
	enableVT()
	fmt.Print(clearScreen)

	go d.loop()
	go d.inputLoop()
}

// Stop halts the dashboard.
func (d *Dashboard) Stop() {
	close(d.stopCh)
	fmt.Print(reset)
}

func (d *Dashboard) loop() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	d.render()

	for {
		select {
		case <-ticker.C:
			// Update Sparkline History
			d.mu.Lock()
			if len(d.ppsHistory) >= d.historyCap {
				d.ppsHistory = d.ppsHistory[1:]
				d.outPPSHistory = d.outPPSHistory[1:]
				d.dropPPSHistory = d.dropPPSHistory[1:]
			}
			d.ppsHistory = append(d.ppsHistory, d.metrics.SnapPPS.Load())
			d.outPPSHistory = append(d.outPPSHistory, d.metrics.SnapOutPPS.Load())
			d.dropPPSHistory = append(d.dropPPSHistory, d.metrics.SnapDropPPS.Load())
			d.mu.Unlock()

			d.render()
		case <-d.stopCh:
			return
		}
	}
}

func (d *Dashboard) inputLoop() {
	buf := make([]byte, 1)
	for {
		select {
		case <-d.stopCh:
			return
		default:
		}

		n, err := os.Stdin.Read(buf)
		if err != nil || n == 0 {
			time.Sleep(100 * time.Millisecond)
			continue
		}

		switch buf[0] {
		case 'q', 'Q':
			fmt.Println("\n" + yellow + "[!] Shutting down WAF..." + reset)
			d.sigCh <- os.Interrupt
			return
		case 'm', 'M':
			d.currentPage = PageMain
			d.render()
		case 'r', 'R':
			d.currentPage = PageAttackRadar
			d.render()
		case 'b', 'B':
			d.currentPage = PageBlacklist
			d.render()
		case 'p', 'P':
			d.currentPage = PagePortInspector
			d.render()
		case 'l', 'L':
			d.currentPage = PageLogs
			d.render()
		case 's', 'S':
			d.currentPage = PageSettings
			d.render()
		case 'h', 'H', '?':
			d.currentPage = PageHelp
			d.render()
		case 'w', 'W':
			newMode := d.eng.GetModeManager().CycleMode()
			d.cfg.SystemMode = newMode
			_ = config.Save(d.configPath, d.cfg)
			d.setFlashMessage(fmt.Sprintf("System Mode changed to: %s", newMode))
			d.render()
		case 'a', 'A':
			d.eng.GetModeManager().SetMode(engine.ModeAuto)
			d.cfg.SystemMode = engine.ModeAuto
			_ = config.Save(d.configPath, d.cfg)
			d.setFlashMessage("Auto AI Defense Active — dynamic adaptive thresholds enabled")
			d.render()
		case '1':
			if d.currentPage == PageSettings {
				ts := d.eng.GetTCPShield()
				var next int
				switch ts.GetMaxConn() {
				case 25:
					next = 50
				case 50:
					next = 100
				case 100:
					next = 200
				case 200:
					next = 500
				case 500:
					next = 25
				default:
					next = 50
				}
				ts.SetMaxConn(int32(next))
				d.cfg.PeaceMode.TCPMaxConnPerIP = int32(next)
				_ = config.Save(d.configPath, d.cfg)
				d.setFlashMessage(fmt.Sprintf("Max TCP Conns per IP set to %d", next))
				d.render()
			}
		case '2':
			if d.currentPage == PageSettings {
				ts := d.eng.GetTCPShield()
				var next int
				switch ts.GetIdleTimeout() {
				case 2:
					next = 5
				case 5:
					next = 10
				case 10:
					next = 30
				case 30:
					next = 2
				default:
					next = 5
				}
				ts.SetIdleTimeout(int64(next))
				d.cfg.PeaceMode.TCPIdleTimeoutSec = int64(next)
				_ = config.Save(d.configPath, d.cfg)
				d.setFlashMessage(fmt.Sprintf("TCP Idle Timeout set to %ds", next))
				d.render()
			}
		case '3':
			if d.currentPage == PageSettings {
				us := d.eng.GetUDPShield()
				var next int
				switch int(us.GetFlowPPS()) {
				case 40:
					next = 80
				case 80:
					next = 150
				case 150:
					next = 300
				case 300:
					next = 40
				default:
					next = 80
				}
				us.SetRateLimits(float64(next), 1048576, us.GetIPPPS(), us.GetSubnetPPS())
				d.cfg.PeaceMode.UDPPPSPerFlow = float64(next)
				_ = config.Save(d.configPath, d.cfg)
				d.setFlashMessage(fmt.Sprintf("UDP Flow Limit set to %d pps", next))
				d.render()
			}
		case '4':
			if d.currentPage == PageSettings {
				us := d.eng.GetUDPShield()
				var next int
				switch int(us.GetIPPPS()) {
				case 100:
					next = 250
				case 250:
					next = 500
				case 500:
					next = 1000
				case 1000:
					next = 100
				default:
					next = 250
				}
				us.SetRateLimits(us.GetFlowPPS(), 1048576, float64(next), us.GetSubnetPPS())
				d.cfg.PeaceMode.UDPPPSPerIP = float64(next)
				_ = config.Save(d.configPath, d.cfg)
				d.setFlashMessage(fmt.Sprintf("UDP Aggregate IP Limit set to %d pps", next))
				d.render()
			}
		case '5':
			if d.currentPage == PageSettings {
				us := d.eng.GetUDPShield()
				var next int
				switch int(us.GetSubnetPPS()) {
				case 200:
					next = 500
				case 500:
					next = 1000
				case 1000:
					next = 2000
				case 2000:
					next = 200
				default:
					next = 500
				}
				us.SetRateLimits(us.GetFlowPPS(), 1048576, us.GetIPPPS(), float64(next))
				d.cfg.PeaceMode.SubnetPPSLimit = float64(next)
				_ = config.Save(d.configPath, d.cfg)
				d.setFlashMessage(fmt.Sprintf("Subnet /24 Limit set to %d pps", next))
				d.render()
			}
		case '6':
			if d.currentPage == PageSettings {
				var nextMode int
				var modeStr string
				switch d.eng.GetEntropyMode() {
				case engine.EntropyModeAuto:
					nextMode = engine.EntropyModeOn
					modeStr = "ON"
				case engine.EntropyModeOn:
					nextMode = engine.EntropyModeOff
					modeStr = "OFF"
				case engine.EntropyModeOff:
					nextMode = engine.EntropyModeAuto
					modeStr = "AUTO"
				default:
					nextMode = engine.EntropyModeAuto
					modeStr = "AUTO"
				}
				d.eng.SetEntropyMode(nextMode)
				d.cfg.WarMode.EntropyMode = modeStr
				_ = config.Save(d.configPath, d.cfg)
				d.setFlashMessage(fmt.Sprintf("Entropy Analysis set to %s", modeStr))
				d.render()
			}
		case '7':
			if d.currentPage == PageSettings {
				var nextMode int
				var modeStr string
				switch d.eng.GetGeoIPMode() {
				case engine.GeoIPModeAuto:
					nextMode = engine.GeoIPModeOn
					modeStr = "ON"
				case engine.GeoIPModeOn:
					nextMode = engine.GeoIPModeOff
					modeStr = "OFF"
				case engine.GeoIPModeOff:
					nextMode = engine.GeoIPModeAuto
					modeStr = "AUTO"
				default:
					nextMode = engine.GeoIPModeAuto
					modeStr = "AUTO"
				}
				d.eng.SetGeoIPMode(nextMode)
				d.cfg.WarMode.GeoIPMode = modeStr
				_ = config.Save(d.configPath, d.cfg)
				d.setFlashMessage(fmt.Sprintf("Geo-IP Defense set to %s", modeStr))
				d.render()
			}
		case '8':
			if d.currentPage == PageSettings {
				us := d.eng.GetUDPShield()
				if us.GameShield != nil {
					newVal := !d.cfg.PeaceMode.EnableGameShield
					us.GameShield.SetEnabled(newVal)
					d.cfg.PeaceMode.EnableGameShield = newVal
					_ = config.Save(d.configPath, d.cfg)
					stateStr := "ENABLED"
					if !newVal {
						stateStr = "DISABLED"
					}
					d.setFlashMessage(fmt.Sprintf("Deep Protocol Shield (DPI): %s", stateStr))
					d.render()
				}

			}
		}
	}
}

func (d *Dashboard) setFlashMessage(msg string) {
	d.mu.Lock()
	d.statusMsg = msg
	d.statusMsgExpiry = time.Now().Add(3 * time.Second)
	d.mu.Unlock()
}

func (d *Dashboard) render() {
	m := d.metrics
	uptime := time.Since(d.startTime).Truncate(time.Second)

	sysMode := d.eng.GetModeManager().GetMode()
	state := d.eng.GetState()
	currentThreat := state.GetMode()

	var modeStr string
	var modeBg string

	switch sysMode {
	case engine.ModeOn:
		modeStr = " [WAR-MODE] "
		modeBg = bgRed + white + bold
	case engine.ModeOff:
		modeStr = " [PEACE-MODE] "
		modeBg = bgBlue + white + bold
	default: // AUTO
		switch currentThreat {
		case engine.ModeUnderSiege:
			modeStr = " [UNDER-SIEGE] "
			modeBg = bgMagenta + white + bold
		case engine.ModeWar:
			modeStr = " [AUTO-WAR] "
			modeBg = bgRed + white + bold
		case engine.ModeElevated:
			modeStr = " [ELEVATED] "
			modeBg = bgYellow + white + bold
		default:
			modeStr = " [AUTO-PEACE] "
			modeBg = bgGreen + white + bold
		}
	}

	setCursorHome()
	var sb strings.Builder
	sb.WriteString(bold + cyan + "╔════════════════════════════════════════════════════════════════════╗\n" + reset)

	renderLine(&sb, reset+bold+white+"  WAF-Shield Enterprise — Windows Universal Anti-DDoS", 68)

	row2 := fmt.Sprintf("  Status: %s[ACTIVE]%s   Threat: %s%s%s   Uptime: %s%s%s",
		bgGreen+white+bold, reset, modeBg, modeStr, reset, bold, formatDuration(uptime), reset)
	renderLine(&sb, row2, 68)

	sb.WriteString(bold + cyan + "╠════════════════════════════════════════════════════════════════════╣\n" + reset)

	// Multi-tab bar
	tabBar := d.renderTabBar()
	renderLine(&sb, tabBar, 68)

	sb.WriteString(bold + cyan + "╠════════════════════════════════════════════════════════════════════╣\n" + reset)

	// Page contents
	switch d.currentPage {
	case PageMain:
		d.renderMainPage(&sb, m)
	case PageAttackRadar:
		d.renderAttackRadarPage(&sb, m)
	case PageBlacklist:
		d.renderBlacklistPage(&sb)
	case PagePortInspector:
		d.renderPortInspectorPage(&sb)
	case PageLogs:
		d.renderLogsPage(&sb)
	case PageSettings:
		d.renderSettingsPage(&sb)
	case PageHelp:
		d.renderHelpPage(&sb)
	}

	sb.WriteString(bold + cyan + "╠════════════════════════════════════════════════════════════════════╣\n" + reset)

	// Status Notification Bar
	d.mu.Lock()
	msg := d.statusMsg
	expiry := d.statusMsgExpiry
	d.mu.Unlock()

	if msg != "" && time.Now().Before(expiry) {
		renderLine(&sb, "  "+green+bold+"[ALERT] "+msg+reset, 68)
	} else {
		diagnosis := d.eng.GetAutoDefense().FormatAttackDiagnosis()
		diagColor := green
		if d.eng.GetState().IsWarMode() {
			diagColor = red + bold
		}
		renderLine(&sb, fmt.Sprintf("  %s[STATUS] %s%s", diagColor, diagnosis, reset), 68)
	}

	sb.WriteString(bold + cyan + "╠════════════════════════════════════════════════════════════════════╣\n" + reset)

	// Navigation shortcuts footer
	footer := fmt.Sprintf("  %s[M]%sMain %s[R]%sRadar %s[B]%sBan %s[P]%sPort %s[L]%sLog %s[S]%sCfg %s[W]%sMode %s[Q]%sQuit",
		yellow+bold, reset, yellow+bold, reset, yellow+bold, reset, yellow+bold, reset, yellow+bold, reset, yellow+bold, reset, yellow+bold, reset, yellow+bold, reset)
	renderLine(&sb, footer, 68)

	sb.WriteString(bold + cyan + "╚════════════════════════════════════════════════════════════════════╝\n" + reset)

	fmt.Print(sb.String())
}

func (d *Dashboard) renderTabBar() string {
	tabs := []struct {
		page ViewPage
		name string
		key  string
	}{
		{PageMain, "Main", "[M]"},
		{PageAttackRadar, "Radar", "[R]"},
		{PageBlacklist, "Bans", "[B]"},
		{PagePortInspector, "Ports", "[P]"},
		{PageLogs, "Logs", "[L]"},
		{PageSettings, "Config", "[S]"},
	}

	var parts []string
	for _, t := range tabs {
		if d.currentPage == t.page {
			parts = append(parts, bgBlue+white+bold+t.key+t.name+reset)
		} else {
			parts = append(parts, dim+t.key+t.name+reset)
		}
	}
	return "  " + strings.Join(parts, " | ")
}

func (d *Dashboard) renderMainPage(sb *strings.Builder, m *stats.Metrics) {
	ports := d.eng.GetDiscovery().GetPorts()
	tcpPorts := sortedPorts(ports.TCP)
	udpPorts := sortedPorts(ports.UDP)

	// Inbound, Outbound & Dropped charts (Sparklines)
	d.mu.Lock()
	ppsSpark := renderSparkline(d.ppsHistory, 10000)
	outSpark := renderSparkline(d.outPPSHistory, 10000)
	dropSpark := renderSparkline(d.dropPPSHistory, 10000)
	d.mu.Unlock()

	row1 := fmt.Sprintf("  %sINBOUND (RX)%s      %s%-9s%s | %-9s | %s",
		yellow, reset, green, formatPPS(m.SnapPPS.Load()), reset, formatBPS(m.SnapBPS.Load()), ppsSpark)
	renderLine(sb, row1, 68)

	rowOut := fmt.Sprintf("  %sOUTBOUND (TX)%s     %s%-9s%s | %-9s | %s",
		cyan, reset, cyan, formatPPS(m.SnapOutPPS.Load()), reset, formatBPS(m.SnapOutBPS.Load()), outSpark)
	renderLine(sb, rowOut, 68)

	dropColor := green
	if m.SnapDropPPS.Load() > 0 {
		dropColor = red
	}
	row2 := fmt.Sprintf("  %sBLOCKED ATTACK%s    %s%-9s%s | %-9s | %s",
		red, reset, dropColor, formatPPS(m.SnapDropPPS.Load()), reset, formatBPS(m.SnapDropBPS.Load()), dropSpark)
	renderLine(sb, row2, 68)

	row3 := fmt.Sprintf("  %sPROTECTED PORTS%s   TCP: %s%-14s%s UDP: %s%-14s%s",
		blue, reset, white, truncPorts(tcpPorts, 14), reset, white, truncPorts(udpPorts, 14), reset)
	renderLine(sb, row3, 68)

	flows := m.ActiveFlows.Load()
	verified := m.VerifiedTCP.Load()
	bans := m.BlacklistedIPs.Load()
	row4 := fmt.Sprintf("  %sACTIVE SESSIONS%s   Flows: %s%-5d%s | TCP: %s%-5d%s | Bans: %s%-4d%s",
		magenta, reset, white, flows, reset, white, verified, reset, red, bans, reset)
	renderLine(sb, row4, 68)

	row5 := fmt.Sprintf("  %sDEFENSE DROPS%s     /24:%s%-4d%s|Refl:%s%-4d%s|DPI:%s%-4d%s|OOS:%s%-4d%s|L1:%s%-4d%s",
		cyan, reset,
		layerColor(m.SnapSubnet.Load()), m.SnapSubnet.Load(), reset,
		layerColor(m.SnapReflection.Load()), m.SnapReflection.Load(), reset,
		layerColor(m.SnapGameQuery.Load()), m.SnapGameQuery.Load(), reset,
		layerColor(m.SnapOutOfState.Load()), m.SnapOutOfState.Load(), reset,
		layerColor(m.SnapL1.Load()), m.SnapL1.Load(), reset)
	renderLine(sb, row5, 68)
}

func (d *Dashboard) renderAttackRadarPage(sb *strings.Builder, m *stats.Metrics) {
	ad := d.eng.GetAutoDefense()
	primary := ad.GetPrimaryAttackVector()

	renderLine(sb, "  "+bold+red+"LIVE ATTACK RADAR & THREAT CLASSIFICATION:"+reset, 68)

	row1 := fmt.Sprintf("  %sPrimary Vector:%s   %s%s%s",
		yellow+bold, reset, bgRed+white+bold, fmt.Sprintf(" %s ", primary), reset)
	renderLine(sb, row1, 68)

	row2 := fmt.Sprintf("  %sDistributed /24:%s  %-6d drops/s  %sUDP Reflection:%s %-6d drops/s",
		dim, reset, m.SnapSubnet.Load(), dim, reset, m.SnapReflection.Load())
	renderLine(sb, row2, 68)

	row3 := fmt.Sprintf("  %sProtocol Query Spam:%-6d drops/s %sTCP Out-of-State:%s%-6d drops/s",
		dim, m.SnapGameQuery.Load(), dim, reset, m.SnapOutOfState.Load())
	renderLine(sb, row3, 68)

	row4 := fmt.Sprintf("  %sL1 Protocol Trash:%s %-6d drops/s  %sClosed Port Scan:%s%-6d drops/s",
		dim, reset, m.SnapL1.Load(), dim, reset, m.SnapL2.Load())
	renderLine(sb, row4, 68)

	renderLine(sb, "  "+cyan+"Mitigation Strategy: Adaptive Heuristic Throttling & Fast Subnet Culling"+reset, 68)
}

func (d *Dashboard) renderBlacklistPage(sb *strings.Builder) {
	renderLine(sb, "  "+bold+red+"ACTIVE BANNED ATTACKERS & QUARANTINED SUBNETS (AUTO-EXPIRING):"+reset, 68)

	var list []string
	list = append(list, d.eng.GetTCPShield().GetBlacklist()...)
	list = append(list, d.eng.GetUDPShield().GetBlacklist()...)

	if len(list) == 0 {
		renderLine(sb, "  (Clean State) — No hosts or subnets currently banned.", 68)
		for i := 0; i < 4; i++ {
			renderLine(sb, "", 68)
		}
	} else {
		for i := 0; i < 5; i++ {
			if i < len(list) {
				renderLine(sb, "  "+list[i], 68)
			} else {
				renderLine(sb, "", 68)
			}
		}
	}
	renderLine(sb, fmt.Sprintf("  Total Quarantined Entries: %s%d%s", bold, len(list), reset), 68)
}

func (d *Dashboard) renderPortInspectorPage(sb *strings.Builder) {
	ports := d.eng.GetDiscovery().GetPorts()
	ad := d.eng.GetAutoDefense()

	renderLine(sb, "  "+bold+cyan+"AUTO-DISCOVERED LISTENING PORTS & DYNAMIC SHIELDS (1-65535):"+reset, 68)

	var allPorts []struct {
		port  uint16
		proto string
	}
	for p := range ports.TCP {
		allPorts = append(allPorts, struct {
			port  uint16
			proto string
		}{p, "TCP"})
	}
	for p := range ports.UDP {
		allPorts = append(allPorts, struct {
			port  uint16
			proto string
		}{p, "UDP"})
	}

	sort.Slice(allPorts, func(i, j int) bool { return allPorts[i].port < allPorts[j].port })

	if len(allPorts) == 0 {
		renderLine(sb, "  Scanning system sockets...", 68)
		for i := 0; i < 4; i++ {
			renderLine(sb, "", 68)
		}
	} else {
		for i := 0; i < 5; i++ {
			if i < len(allPorts) {
				item := allPorts[i]
				profile := ad.GetPortProfile(item.port)
				line := fmt.Sprintf("  %s%-5d/%s%s │ Shield: %s%-36s%s",
					green+bold, item.port, item.proto, reset, white, profile, reset)
				renderLine(sb, line, 68)
			} else {
				renderLine(sb, "", 68)
			}
		}
	}
	renderLine(sb, fmt.Sprintf("  Total Active Listening Ports: %s%d%s", bold, len(allPorts), reset), 68)
}

func (d *Dashboard) renderLogsPage(sb *strings.Builder) {
	fl := d.eng.GetFastLogger()
	renderLine(sb, "  "+bold+yellow+"LIVE SECURITY EVENT STREAM (IN-MEMORY RING BUFFER):"+reset, 68)

	if fl == nil {
		renderLine(sb, "  FastLogger inactive.", 68)
		return
	}

	events := fl.GetRecentEvents(5)
	if len(events) == 0 {
		renderLine(sb, "  Waiting for security events...", 68)
		for i := 0; i < 4; i++ {
			renderLine(sb, "", 68)
		}
	} else {
		for i := 0; i < 5; i++ {
			if i < len(events) {
				ev := events[i]
				var lvlColor string
				switch ev.Level {
				case logger.LevelAttack:
					lvlColor = red + bold
				case logger.LevelBan:
					lvlColor = bgRed + white + bold
				case logger.LevelWarn:
					lvlColor = yellow + bold
				default:
					lvlColor = cyan
				}
				timeStr := ev.Timestamp.Format("15:04:05")
				line := fmt.Sprintf("  [%s] %s%-6s%s [%-7s] %s", timeStr, lvlColor, ev.Level.String(), reset, ev.Category, ev.Message)
				renderLine(sb, line, 68)
			} else {
				renderLine(sb, "", 68)
			}
		}
	}
	renderLine(sb, fmt.Sprintf("  Dropped Log Events (Backpressure): %s%d%s", bold, fl.GetDroppedLogsCount(), reset), 68)
}

func (d *Dashboard) renderSettingsPage(sb *strings.Builder) {
	ts := d.eng.GetTCPShield()
	us := d.eng.GetUDPShield()

	renderLine(sb, "  "+bold+yellow+"DYNAMIC FIREWALL RULES & LIVE TUNING [PRESS 1-8]:"+reset, 68)

	row1 := fmt.Sprintf("  %s[1]%s Max TCP Conns/IP:   %s%-6d%s %s[2]%s TCP Idle Timeout:    %s%ds%s",
		yellow+bold, reset, white+bold, ts.GetMaxConn(), reset, yellow+bold, reset, white+bold, ts.GetIdleTimeout(), reset)
	renderLine(sb, row1, 68)

	row2 := fmt.Sprintf("  %s[3]%s UDP Flow PPS Limit:  %s%-6s%s %s[4]%s UDP IP PPS Limit:    %s%s%s",
		yellow+bold, reset, white+bold, formatPPS(uint64(us.GetFlowPPS())), reset, yellow+bold, reset, white+bold, formatPPS(uint64(us.GetIPPPS())), reset)
	renderLine(sb, row2, 68)

	row3 := fmt.Sprintf("  %s[5]%s Subnet /24 PPS Limit:%s%-6s%s %s[6]%s UDP Entropy Check:   %s%s%s",
		yellow+bold, reset, white+bold, formatPPS(uint64(us.GetSubnetPPS())), reset, yellow+bold, reset, white+bold, modeName(d.eng.GetEntropyMode()), reset)
	renderLine(sb, row3, 68)

	dpiShieldStatus := green + "ON" + reset
	if !d.cfg.PeaceMode.EnableGameShield {
		dpiShieldStatus = red + "OFF" + reset
	}
	row4 := fmt.Sprintf("  %s[7]%s Geo-IP Defense:      %s%-6s%s %s[8]%s Deep Protocol DPI:  %s",
		yellow+bold, reset, white+bold, modeName(d.eng.GetGeoIPMode()), reset, yellow+bold, reset, dpiShieldStatus)
	renderLine(sb, row4, 68)

	renderLine(sb, "  * Changes take effect instantly in kernel memory without restart.", 68)
}

func (d *Dashboard) renderHelpPage(sb *strings.Builder) {
	renderLine(sb, "  "+bold+cyan+"KEYBOARD SHORTCUTS & DOCUMENTATION:"+reset, 68)
	renderLine(sb, "  [M] Main Dashboard    [R] Attack Radar       [B] Blacklist Manager", 68)
	renderLine(sb, "  [P] Port Inspector    [L] Live Event Logs    [S] Live Configuration", 68)
	renderLine(sb, "  [W] Cycle Mode (AUTO/WAR/PEACE)              [A] Force AUTO Mode", 68)
	renderLine(sb, "  [Q] Graceful Shutdown (Unloads WinDivert kernel driver safely)", 68)
	renderLine(sb, "  * Optimized for Windows 2012/2016/2019/2022 & Windows 10/11.", 68)
}

// Sparklines rendering using unicode block elements:  ▂▃▄▅▆▇█

func renderSparkline(history []uint64, maxVal uint64) string {
	const limit = 12
	if len(history) == 0 {
		return strings.Repeat("-", limit)
	}
	var blocks []rune
	if supportsANSI {
		blocks = []rune{' ', ' ', '▂', '▃', '▄', '▅', '▆', '▇', '█'}
	} else {
		blocks = []rune{'.', '.', '-', '=', '#', '#', '#', '#', '#'}
	}

	var localMax uint64 = 1
	for _, v := range history {
		if v > localMax {
			localMax = v
		}
	}
	if maxVal > localMax {
		localMax = maxVal
	}

	var sb strings.Builder
	start := 0
	if len(history) > limit {
		start = len(history) - limit
	}
	for i := start; i < len(history); i++ {
		v := history[i]
		if v == 0 {
			sb.WriteRune(' ')
			continue
		}
		idx := int((float64(v) / float64(localMax)) * float64(len(blocks)-1))
		if idx >= len(blocks) {
			idx = len(blocks) - 1
		}
		if idx < 1 {
			idx = 1
		}
		sb.WriteRune(blocks[idx])
	}
	if sb.Len() < limit {
		sb.WriteString(strings.Repeat(" ", limit-sb.Len()))
	}
	return cyan + sb.String() + reset
}

func formatPPS(pps uint64) string {
	if pps >= 1000000 {
		return fmt.Sprintf("%.1fM pps", float64(pps)/1000000)
	}
	if pps >= 1000 {
		return fmt.Sprintf("%.1fK pps", float64(pps)/1000)
	}
	return fmt.Sprintf("%d pps", pps)
}

func formatBPS(bps uint64) string {
	if bps >= 1073741824 {
		return fmt.Sprintf("%.1f Gbps", float64(bps)*8/1073741824)
	}
	if bps >= 1048576 {
		return fmt.Sprintf("%.1f Mbps", float64(bps)*8/1048576)
	}
	if bps >= 1024 {
		return fmt.Sprintf("%.1f Kbps", float64(bps)*8/1024)
	}
	return fmt.Sprintf("%d bps", bps*8)
}

func formatDuration(d time.Duration) string {
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	return fmt.Sprintf("%02d:%02d:%02d", h, m, s)
}

func sortedPorts(m map[uint16]bool) []uint16 {
	ports := make([]uint16, 0, len(m))
	for p := range m {
		ports = append(ports, p)
	}
	sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
	return ports
}

func truncPorts(ports []uint16, maxLen int) string {
	if len(ports) == 0 {
		return "(none)"
	}
	parts := make([]string, 0, len(ports))
	for _, p := range ports {
		parts = append(parts, fmt.Sprintf("%d", p))
	}
	s := strings.Join(parts, ",")
	if len(s) > maxLen {
		s = s[:maxLen-3] + "..."
	}
	return s
}

func layerColor(count uint64) string {
	if count > 100 {
		return red + bold
	}
	if count > 0 {
		return yellow
	}
	return green
}

func modeName(mode int) string {
	switch mode {
	case engine.EntropyModeOn:
		return "ON"
	case engine.EntropyModeOff:
		return "OFF"
	default:
		return "AUTO"
	}
}

func enableVT() {
	// Handled in main.go
}

func visualLen(s string) int {
	inEscape := false
	length := 0
	runes := []rune(s)
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		if r == '\033' {
			inEscape = true
			continue
		}
		if inEscape {
			if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') {
				inEscape = false
			}
			continue
		}
		length++
	}
	return length
}

func renderLine(sb *strings.Builder, content string, width int) {
	vLen := visualLen(content)
	padding := width - vLen
	sb.WriteString(bold + cyan + "║" + reset + content)
	if padding > 0 {
		sb.WriteString(strings.Repeat(" ", padding))
	}
	sb.WriteString(bold + cyan + "║\n" + reset)
}
