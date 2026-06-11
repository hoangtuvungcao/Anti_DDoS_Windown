package cli

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"waf-game/pkg/config"
	"waf-game/pkg/engine"
	"waf-game/pkg/stats"
)

// ANSI escape codes
const (
	clearScreen = "\033[2J\033[H" // Clear screen and move cursor to home
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
	dim         = "\033[2m"
)

type ViewPage int

const (
	PageMain ViewPage = iota
	PageBlacklist
	PageSettings
)

// Dashboard is the CLI terminal dashboard.
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
}

// NewDashboard creates a new CLI dashboard.
func NewDashboard(metrics *stats.Metrics, eng *engine.Engine, sigCh chan<- os.Signal, cfg *config.Config, configPath string) *Dashboard {
	return &Dashboard{
		metrics:     metrics,
		eng:         eng,
		cfg:         cfg,
		configPath:  configPath,
		startTime:   time.Now(),
		stopCh:      make(chan struct{}),
		sigCh:       sigCh,
		currentPage: PageMain,
	}
}

// Start begins the dashboard refresh loop.
func (d *Dashboard) Start() {
	// Enable virtual terminal processing on Windows
	enableVT()
	fmt.Print(clearScreen) // Thoroughly clear screen on startup

	go d.loop()
	go d.inputLoop()
}

// Stop halts the dashboard.
func (d *Dashboard) Stop() {
	close(d.stopCh)
	fmt.Print(reset) // Reset terminal colors
}

func (d *Dashboard) loop() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	// Initial render
	d.render()

	for {
		select {
		case <-ticker.C:
			d.metrics.Snapshot()
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
			fmt.Println("\n" + yellow + "[!] Shutting down..." + reset)
			d.sigCh <- os.Interrupt
			return
		case 'w', 'W':
			// Cycle system mode: AUTO -> ON -> OFF -> AUTO
			newMode := d.eng.GetModeManager().CycleMode()
			d.cfg.SystemMode = newMode
			_ = config.Save(d.configPath, d.cfg)
			d.mu.Lock()
			d.statusMsg = fmt.Sprintf("System Mode changed to: %s", newMode)
			d.statusMsgExpiry = time.Now().Add(3 * time.Second)
			d.mu.Unlock()
			d.render()
		case 'a', 'A':
			// Force AUTO mode
			d.eng.GetModeManager().SetMode(engine.ModeAuto)
			d.cfg.SystemMode = engine.ModeAuto
			_ = config.Save(d.configPath, d.cfg)
			d.mu.Lock()
			d.statusMsg = "System Mode: AUTO — dynamic escalation enabled"
			d.statusMsgExpiry = time.Now().Add(3 * time.Second)
			d.mu.Unlock()
			d.render()
		case 'm', 'M':
			d.currentPage = PageMain
			d.render()
		case 'b', 'B':
			d.currentPage = PageBlacklist
			d.render()
		case 's', 'S':
			d.currentPage = PageSettings
			d.render()
		case '1':
			if d.currentPage == PageSettings {
				// Cycle Max TCP Connections: 100 -> 200 -> 500 -> 1000 -> 50
				ts := d.eng.GetTCPShield()
				var next int
				switch ts.GetMaxConn() {
				case 50:
					next = 100
				case 100:
					next = 200
				case 200:
					next = 500
				case 500:
					next = 1000
				case 1000:
					next = 50
				default:
					next = 100
				}
				ts.SetMaxConn(int32(next))
				d.cfg.PeaceMode.TCPMaxConnPerIP = int32(next)
				_ = config.Save(d.configPath, d.cfg)
				d.mu.Lock()
				d.statusMsg = fmt.Sprintf("Max TCP connections per IP set to %d", next)
				d.statusMsgExpiry = time.Now().Add(3 * time.Second)
				d.mu.Unlock()
				d.render()
			}
		case '2':
			if d.currentPage == PageSettings {
				// Cycle TCP Idle Timeout: 5 -> 10 -> 30 -> 2
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
				d.mu.Lock()
				d.statusMsg = fmt.Sprintf("TCP Idle Timeout set to %ds", next)
				d.statusMsgExpiry = time.Now().Add(3 * time.Second)
				d.mu.Unlock()
				d.render()
			}
		case '3':
			if d.currentPage == PageSettings {
				// Cycle UDP Flow PPS: 150 -> 300 -> 500 -> 1000 -> 50
				us := d.eng.GetUDPShield()
				var next int
				switch us.GetFlowPPS() {
				case 50:
					next = 150
				case 150:
					next = 300
				case 300:
					next = 500
				case 500:
					next = 1000
				case 1000:
					next = 50
				default:
					next = 150
				}
				us.SetRateLimits(float64(next), 1048576, us.GetIPPPS())
				d.cfg.PeaceMode.UDPPPSPerFlow = float64(next)
				_ = config.Save(d.configPath, d.cfg)
				d.mu.Lock()
				d.statusMsg = fmt.Sprintf("UDP Flow PPS Limit set to %d pps", next)
				d.statusMsgExpiry = time.Now().Add(3 * time.Second)
				d.mu.Unlock()
				d.render()
			}
		case '4':
			if d.currentPage == PageSettings {
				// Cycle UDP IP PPS: 500 -> 1000 -> 2000 -> 5000 -> 100
				us := d.eng.GetUDPShield()
				var next int
				switch us.GetIPPPS() {
				case 100:
					next = 500
				case 500:
					next = 1000
				case 1000:
					next = 2000
				case 2000:
					next = 5000
				case 5000:
					next = 100
				default:
					next = 500
				}
				us.SetRateLimits(us.GetFlowPPS(), 1048576, float64(next))
				d.cfg.PeaceMode.UDPPPSPerIP = float64(next)
				_ = config.Save(d.configPath, d.cfg)
				d.mu.Lock()
				d.statusMsg = fmt.Sprintf("UDP IP PPS Limit set to %d pps", next)
				d.statusMsgExpiry = time.Now().Add(3 * time.Second)
				d.mu.Unlock()
				d.render()
			}
		case '5':
			if d.currentPage == PageSettings {
				// Cycle UDP Entropy Mode: AUTO -> ON -> OFF -> AUTO
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
				d.mu.Lock()
				d.statusMsg = fmt.Sprintf("UDP Entropy Analysis Mode set to %s", modeStr)
				d.statusMsgExpiry = time.Now().Add(3 * time.Second)
				d.mu.Unlock()
				d.render()
			}
		case '6':
			if d.currentPage == PageSettings {
				// Cycle GeoIP Mode: AUTO -> ON -> OFF -> AUTO
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
				d.mu.Lock()
				d.statusMsg = fmt.Sprintf("Geo-IP Block Mode set to %s", modeStr)
				d.statusMsgExpiry = time.Now().Add(3 * time.Second)
				d.mu.Unlock()
				d.render()
			}
		}
	}
}

func (d *Dashboard) render() {
	m := d.metrics
	uptime := time.Since(d.startTime).Truncate(time.Second)

	// Mode display — composed from system mode + current state
	sysMode := d.eng.GetModeManager().GetMode()
	var modeStr string
	var modeBg string
	state := d.eng.GetState()
	isWar := state.IsWarMode()

	switch sysMode {
	case engine.ModeOn:
		modeStr = " ⚔ ON-WAR "
		modeBg = bgRed + white + bold
	case engine.ModeOff:
		modeStr = " 🛡 OFF-PEACE "
		modeBg = bgBlue + white + bold
	default: // AUTO
		if isWar {
			modeStr = " ⚔ AUTO-WAR "
			modeBg = bgRed + white + bold
		} else {
			modeStr = " 🛡 AUTO-PEACE "
			modeBg = bgGreen + white + bold
		}
	}

	var sb strings.Builder

	// Cursor home (rewrite in place — no flicker)
	sb.WriteString(cursorHome)

	// Top border
	sb.WriteString(bold + cyan + "╔══════════════════════════════════════════════════════════════════╗" + clearLine + "\n")

	// Header line
	renderLine(&sb, reset+bold+white+"  WAF-Game v1.0 — Anti-DDoS Firewall for Windows", 66)

	row2 := fmt.Sprintf("  Status: %s%s ACTIVE %s   Mode: %s%s%s   Uptime: %s%s%s",
		bgGreen+white+bold, "██", reset, modeBg, modeStr, reset, bold, formatDuration(uptime), reset)
	renderLine(&sb, row2, 66)

	// Separator
	sb.WriteString(bold + cyan + "╠══════════════════════════════════════════════════════════════════╣" + clearLine + "\n")

	// Navigation Tab Bar
	var tabMain, tabBlacklist, tabSettings string
	if d.currentPage == PageMain {
		tabMain = bgBlue + white + bold + " [M] Main Dashboard " + reset
		tabBlacklist = " [B] Blacklist "
		tabSettings = " [S] Settings "
	} else if d.currentPage == PageBlacklist {
		tabMain = " [M] Main Dashboard "
		tabBlacklist = bgBlue + white + bold + " [B] Blacklist " + reset
		tabSettings = " [S] Settings "
	} else {
		tabMain = " [M] Main Dashboard "
		tabBlacklist = " [B] Blacklist "
		tabSettings = bgBlue + white + bold + " [S] Settings " + reset
	}
	tabBar := fmt.Sprintf("  %s  │  %s  │  %s", tabMain, tabBlacklist, tabSettings)
	renderLine(&sb, tabBar, 66)

	// Separator
	sb.WriteString(bold + cyan + "╠══════════════════════════════════════════════════════════════════╣" + clearLine + "\n")

	// Page content
	switch d.currentPage {
	case PageMain:
		d.renderMainPage(&sb, m)
	case PageBlacklist:
		d.renderBlacklistPage(&sb)
	case PageSettings:
		d.renderSettingsPage(&sb)
	}

	// Separator
	sb.WriteString(bold + cyan + "╠══════════════════════════════════════════════════════════════════╣" + clearLine + "\n")

	// Status Message / Notification Area
	d.mu.Lock()
	msg := d.statusMsg
	expiry := d.statusMsgExpiry
	d.mu.Unlock()

	if msg != "" && time.Now().Before(expiry) {
		renderLine(&sb, "  "+green+bold+"🔔 "+msg+reset, 65)
	} else {
		renderLine(&sb, "", 66)
	}

	// Separator
	sb.WriteString(bold + cyan + "╠══════════════════════════════════════════════════════════════════╣" + clearLine + "\n")

	// Footer instructions
	footer := fmt.Sprintf("  %s[M]%s Home  %s[B]%s Black  %s[S]%s Config  %s[W]%s Mode  %s[A]%s Auto  %s[Q]%s Quit",
		yellow+bold, reset, yellow+bold, reset, yellow+bold, reset, yellow+bold, reset, yellow+bold, reset, yellow+bold, reset)
	renderLine(&sb, footer, 66)

	// Bottom border
	sb.WriteString(bold + cyan + "╚══════════════════════════════════════════════════════════════════╝" + clearLine + "\n" + reset)

	fmt.Print(sb.String())
}

func (d *Dashboard) renderMainPage(sb *strings.Builder, m *stats.Metrics) {
	ports := d.eng.GetDiscovery().GetPorts()
	tcpPorts := sortedPorts(ports.TCP)
	udpPorts := sortedPorts(ports.UDP)

	// Traffic stats
	row1 := fmt.Sprintf("  %s📊 Traffic%s      Inbound: %s%-8s%s │ %s",
		yellow, reset, green, formatPPS(m.SnapPPS), reset, formatBPS(m.SnapBPS))
	renderLine(sb, row1, 66)

	dropColor := green
	if m.SnapDropPPS > 0 {
		dropColor = red
	}
	row2 := fmt.Sprintf("                  Dropped: %s%-8s%s │ %s",
		dropColor, formatPPS(m.SnapDropPPS), reset, formatBPS(m.SnapDropBPS))
	renderLine(sb, row2, 66)

	// Protected ports (trunced to 22 characters max list length)
	row3 := fmt.Sprintf("  %s🔒 Protected%s    TCP: %s%-22s%s",
		blue, reset, white, truncPorts(tcpPorts, 22), reset)
	renderLine(sb, row3, 66)

	row4 := fmt.Sprintf("                  UDP: %s%-22s%s",
		white, truncPorts(udpPorts, 22), reset)
	renderLine(sb, row4, 66)

	// Blacklist & flows
	flows := m.ActiveFlows.Load()
	verified := m.VerifiedTCP.Load()
	row5 := fmt.Sprintf("  %s📡 Flows%s        UDP: %s%-6d%s │ TCP Verified: %s%-6d%s",
		magenta, reset, white, flows, reset, white, verified, reset)
	renderLine(sb, row5, 66)

	// Layer stats
	row6 := fmt.Sprintf("  %s⚡ Drops/s%s      L1:%s%-5d%s │ L2:%s%-5d%s │ L3:%s%-5d%s │ L4:%s%-5d%s",
		red, reset,
		layerColor(m.SnapL1), m.SnapL1, reset,
		layerColor(m.SnapL2), m.SnapL2, reset,
		layerColor(m.SnapL3), m.SnapL3, reset,
		layerColor(m.SnapL4), m.SnapL4, reset)
	renderLine(sb, row6, 66)
}

func (d *Dashboard) renderBlacklistPage(sb *strings.Builder) {
	renderLine(sb, "  "+bold+red+"🚫 Active Blacklisted IPs and Flows (Auto-expiring):"+reset, 66)

	// Collect lists from shields
	var list []string
	list = append(list, d.eng.GetTCPShield().GetBlacklist()...)
	list = append(list, d.eng.GetUDPShield().GetBlacklist()...)

	if len(list) == 0 {
		renderLine(sb, "  (none) - System is in clean state.", 66)
		// Empty space padding
		for i := 0; i < 4; i++ {
			renderLine(sb, "", 66)
		}
	} else {
		for i := 0; i < 5; i++ {
			if i < len(list) {
				renderLine(sb, "  "+list[i], 66)
			} else {
				renderLine(sb, "", 66)
			}
		}
	}
	renderLine(sb, fmt.Sprintf("  Total Blacklisted Entries: %s%d%s", bold, len(list), reset), 66)
}

func (d *Dashboard) renderSettingsPage(sb *strings.Builder) {
	ts := d.eng.GetTCPShield()
	us := d.eng.GetUDPShield()

	renderLine(sb, "  "+bold+yellow+"⚙ Dynamic Shield Rules & Configurations:"+reset, 66)

	row1 := fmt.Sprintf("  %s[1]%s Max TCP Connections per IP: %s%d%s",
		yellow+bold, reset, white+bold, ts.GetMaxConn(), reset)
	renderLine(sb, row1, 66)

	row2 := fmt.Sprintf("  %s[2]%s TCP Idle Timeout:            %s%ds%s",
		yellow+bold, reset, white+bold, ts.GetIdleTimeout(), reset)
	renderLine(sb, row2, 66)

	row3 := fmt.Sprintf("  %s[3]%s UDP Flow PPS Limit:          %s%s%s",
		yellow+bold, reset, white+bold, formatPPS(uint64(us.GetFlowPPS())), reset)
	renderLine(sb, row3, 66)

	row4 := fmt.Sprintf("  %s[4]%s UDP IP PPS Limit:            %s%s%s",
		yellow+bold, reset, white+bold, formatPPS(uint64(us.GetIPPPS())), reset)
	renderLine(sb, row4, 66)

	var entropyStatus string
	switch d.eng.GetEntropyMode() {
	case engine.EntropyModeOn:
		entropyStatus = green + "ON" + reset
	case engine.EntropyModeOff:
		entropyStatus = red + "OFF" + reset
	case engine.EntropyModeAuto:
		entropyStatus = cyan + "AUTO" + reset
	default:
		entropyStatus = cyan + "AUTO" + reset
	}
	row5 := fmt.Sprintf("  %s[5]%s UDP Entropy Analysis Check:  %s",
		yellow+bold, reset, entropyStatus)
	renderLine(sb, row5, 66)

	var geoStatus string
	switch d.eng.GetGeoIPMode() {
	case engine.GeoIPModeOn:
		geoStatus = green + "ON" + reset
	case engine.GeoIPModeOff:
		geoStatus = red + "OFF" + reset
	case engine.GeoIPModeAuto:
		geoStatus = cyan + "AUTO" + reset
	default:
		geoStatus = cyan + "AUTO" + reset
	}
	row6 := fmt.Sprintf("  %s[6]%s Geo-IP Block Mode (VN-only): %s",
		yellow+bold, reset, geoStatus)
	renderLine(sb, row6, 66)

	renderLine(sb, "  * Press numeric key [1-6] to dynamically adjust settings.", 66)
}

// Helper functions

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
	return fmt.Sprintf("%s (%d ports)", s, len(ports))
}

func layerColor(count uint64) string {
	if count > 100 {
		return red
	}
	if count > 0 {
		return yellow
	}
	return green
}

func enableVT() {
	// Handled by main.go enableConsoleVT()
}

// visualLen returns the printed columns of a string, omitting ANSI codes and counting emojis as double-width.
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
		// Count Emojis used in UI as double-width (except ⚡ which is single-width in Windows console, and including 🚫 and ⚔)
		if r == '📊' || r == '🔒' || r == '📡' || r == '🛡' || r == '🚫' || r == '⚔' {
			length += 2
		} else {
			length++
		}
	}
	return length
}

// renderLine draws the borders and aligns the content by padding spaces.
func renderLine(sb *strings.Builder, content string, width int) {
	vLen := visualLen(content)
	padding := width - vLen
	sb.WriteString(bold + cyan + "║" + reset + content)
	if padding > 0 {
		sb.WriteString(strings.Repeat(" ", padding))
	}
	sb.WriteString(bold + cyan + "║" + clearLine + "\n")
}
