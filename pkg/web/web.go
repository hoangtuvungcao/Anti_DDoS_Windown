package web

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"

	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"waf-game/pkg/engine"
	"waf-game/pkg/logger"
	"waf-game/pkg/stats"
)

//go:embed app_256.png
var logoPNG []byte

//go:embed app.ico
var faviconICO []byte

// WebConfig holds settings for the embedded web dashboard.
type WebConfig struct {
	Enabled  bool   `json:"enabled"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	AllowLAN bool   `json:"allow_lan"`
}

// Server provides the embedded web dashboard and REST API.
type Server struct {
	cfg          WebConfig
	engine       *engine.Engine
	metrics      *stats.Metrics
	fastLog      *logger.FastLogger
	httpSrv      *http.Server
	startTime    time.Time
	activePreset string
	mu           sync.Mutex
}

// NewServer initializes the embedded web server.
func NewServer(cfg WebConfig, eng *engine.Engine, metrics *stats.Metrics, fastLog *logger.FastLogger) *Server {
	if cfg.Port <= 0 {
		cfg.Port = 8080
	}

	return &Server{
		cfg:          cfg,
		engine:       eng,
		metrics:      metrics,
		fastLog:      fastLog,
		startTime:    time.Now(),
		activePreset: "HYBRID",
	}
}

// Start launches the HTTP server in a background goroutine.
func (s *Server) Start() error {
	if !s.cfg.Enabled {
		return nil
	}
	if s.cfg.AllowLAN && (s.cfg.Username == "" || s.cfg.Password == "") {
		return fmt.Errorf("refusing unauthenticated LAN dashboard; set username/password or allow_lan=false")
	}
	if (s.cfg.Username == "") != (s.cfg.Password == "") {
		return fmt.Errorf("dashboard username and password must both be set")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/x-icon")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		_, _ = w.Write(faviconICO)
	})
	mux.HandleFunc("/logo.png", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		_, _ = w.Write(logoPNG)
	})
	mux.HandleFunc("/", s.authMiddleware(s.handleDashboard))
	mux.HandleFunc("/api/stats", s.authMiddleware(s.handleAPIStats))
	mux.HandleFunc("/api/bans", s.authMiddleware(s.handleAPIBans))
	mux.HandleFunc("/api/ban", s.authMiddleware(s.handleAPIBanManual))
	mux.HandleFunc("/api/unban", s.authMiddleware(s.handleAPIUnbanManual))
	mux.HandleFunc("/api/whitelist", s.authMiddleware(s.handleAPIWhitelist))
	mux.HandleFunc("/api/whitelist/remove", s.authMiddleware(s.handleAPIWhitelistRemove))
	mux.HandleFunc("/api/preset", s.authMiddleware(s.handleAPIPreset))
	mux.HandleFunc("/api/ports", s.authMiddleware(s.handleAPIPorts))
	mux.HandleFunc("/api/logs", s.authMiddleware(s.handleAPILogs))
	mux.HandleFunc("/api/mode", s.authMiddleware(s.handleAPIMode))
	mux.HandleFunc("/api/geoip", s.authMiddleware(s.handleAPIGeoIP))

	bindAddr := fmt.Sprintf("127.0.0.1:%d", s.cfg.Port)
	if s.cfg.AllowLAN {
		bindAddr = fmt.Sprintf("0.0.0.0:%d", s.cfg.Port)
	}

	s.httpSrv = &http.Server{
		Addr:              bindAddr,
		Handler:           mux,
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}

	listener, err := net.Listen("tcp", bindAddr)
	if err != nil {
		return fmt.Errorf("start dashboard on %s: %w", bindAddr, err)
	}
	go func() {
		if err := s.httpSrv.Serve(listener); err != nil && err != http.ErrServerClosed && s.fastLog != nil {
			s.fastLog.Error("WEB", "Dashboard server stopped unexpectedly: %v", err)
		}
	}()

	return nil
}

// Stop stops the web server gracefully.
func (s *Server) Stop() {
	if s.httpSrv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.httpSrv.Shutdown(ctx)
	}
}

func (s *Server) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		if s.cfg.Username != "" && s.cfg.Password != "" {
			user, pass, ok := r.BasicAuth()
			userHash := sha256.Sum256([]byte(user))
			passHash := sha256.Sum256([]byte(pass))
			expectedUser := sha256.Sum256([]byte(s.cfg.Username))
			expectedPass := sha256.Sum256([]byte(s.cfg.Password))
			valid := subtle.ConstantTimeCompare(userHash[:], expectedUser[:]) & subtle.ConstantTimeCompare(passHash[:], expectedPass[:])
			if !ok || valid != 1 {
				w.Header().Set("WWW-Authenticate", `Basic realm="WAF-Shield Cyber Security"`)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
		}
		next(w, r)
	}
}

func (s *Server) handleAPIStats(w http.ResponseWriter, r *http.Request) {
	m := s.metrics
	ad := s.engine.GetAutoDefense()
	state := s.engine.GetState()
	mm := s.engine.GetModeManager()

	var threatStr string
	switch state.GetMode() {
	case engine.ModeUnderSiege:
		threatStr = "UNDER_SIEGE"
	case engine.ModeWar:
		threatStr = "WAR"
	case engine.ModeElevated:
		threatStr = "ELEVATED"
	default:
		threatStr = "PEACE"
	}

	passedPPS := uint64(0)
	if m.SnapPPS.Load() > m.SnapDropPPS.Load() {
		passedPPS = m.SnapPPS.Load() - m.SnapDropPPS.Load()
	}

	passedBPS := uint64(0)
	if m.SnapBPS.Load() > m.SnapDropBPS.Load() {
		passedBPS = m.SnapBPS.Load() - m.SnapDropBPS.Load()
	}

	geoModeStr := "AUTO"
	switch s.engine.GetGeoIPMode() {
	case engine.GeoIPModeOn:
		geoModeStr = "ON (VN Only)"
	case engine.GeoIPModeOff:
		geoModeStr = "OFF (Worldwide)"
	default:
		geoModeStr = "AUTO"
	}

	s.mu.Lock()
	activePreset := s.activePreset
	s.mu.Unlock()

	data := map[string]interface{}{
		"status":            "ACTIVE",
		"system_mode":       string(mm.GetMode()),
		"threat_mode":       threatStr,
		"active_preset":     activePreset,
		"primary_vector":    string(ad.GetPrimaryAttackVector()),
		"attack_diagnosis":  ad.FormatAttackDiagnosis(),
		"geoip_mode":        geoModeStr,
		"uptime_sec":        int(time.Since(s.startTime).Seconds()),
		"inbound_pps":       m.SnapPPS.Load(),
		"passed_pps":        passedPPS,
		"outbound_pps":      m.SnapOutPPS.Load(),
		"dropped_pps":       m.SnapDropPPS.Load(),
		"inbound_bps":       m.SnapBPS.Load(),
		"passed_bps":        passedBPS,
		"outbound_bps":      m.SnapOutBPS.Load(),
		"dropped_bps":       m.SnapDropBPS.Load(),
		"active_flows":      s.engine.GetUDPShield().GetFlowCount(),
		"active_tcp":        s.engine.GetTCPShield().GetVerifiedCount(),
		"total_bans":        m.BlacklistedIPs.Load(),
		"drops_subnet":      m.SnapSubnet.Load(),
		"drops_refl":        m.SnapReflection.Load(),
		"drops_dpi":         m.SnapGameQuery.Load(),
		"drops_entropy":     m.SnapEntropy.Load(),
		"drops_unverified":  m.SnapUnverified.Load(),
		"drops_oos":         m.SnapOutOfState.Load(),
		"drops_l1":          m.SnapL1.Load(),
		"drops_l2":          m.SnapL2.Load(),
		"botnet_detected":   m.BotnetDetected.Load(),
		"unique_source_ips": m.UniqueSourceIPs.Load(),
		"unique_subnets":    m.UniqueSubnets.Load(),
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(data)

}

func (s *Server) handleAPIBans(w http.ResponseWriter, r *http.Request) {
	var list []string
	list = append(list, s.engine.GetTCPShield().GetBlacklist()...)
	list = append(list, s.engine.GetUDPShield().GetBlacklist()...)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"total": len(list),
		"bans":  list,
	})
}

func (s *Server) handleAPIBanManual(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ipStr := r.URL.Query().Get("ip")
	durStr := r.URL.Query().Get("dur")

	ip := net.ParseIP(ipStr)
	if ip == nil {
		http.Error(w, "Invalid IP address", http.StatusBadRequest)
		return
	}

	durMin := 10
	if durStr != "" {
		if d, err := strconv.Atoi(durStr); err == nil && d > 0 {
			durMin = d
		}
	}

	s.engine.GetIPFilter().AddBlacklist(ipStr, time.Duration(durMin)*time.Minute)
	if s.fastLog != nil {
		s.fastLog.Warn("ADMIN", "Manual ban added: %s for %d minutes", ipStr, durMin)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status": "success",
		"msg":    fmt.Sprintf("Blacklisted %s for %d minutes", ipStr, durMin),
	})
}

func (s *Server) handleAPIUnbanManual(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ipStr := r.URL.Query().Get("ip")
	ip := net.ParseIP(ipStr)
	if ip == nil {
		http.Error(w, "Invalid IP address", http.StatusBadRequest)
		return
	}

	if ip4 := ip.To4(); ip4 != nil {
		var b [4]byte
		copy(b[:], ip4)
		s.engine.GetIPFilter().RemoveBlacklist(b)
	}

	if s.fastLog != nil {
		s.fastLog.Info("ADMIN", "Manual unban: %s removed from blacklist", ipStr)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status": "success",
		"msg":    fmt.Sprintf("Removed %s from blacklist", ipStr),
	})
}

func (s *Server) handleAPIWhitelist(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		ipStr := r.URL.Query().Get("ip")
		ip := net.ParseIP(ipStr)
		if ip == nil {
			http.Error(w, "Invalid IP address", http.StatusBadRequest)
			return
		}
		s.engine.GetIPFilter().AddWhitelist(ipStr)
		if s.fastLog != nil {
			s.fastLog.Info("ADMIN", "Added to whitelist: %s", ipStr)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status": "success",
			"msg":    fmt.Sprintf("Whitelisted %s", ipStr),
		})
		return
	}

	list := s.engine.GetIPFilter().GetWhitelist()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"total":     len(list),
		"whitelist": list,
	})
}

func (s *Server) handleAPIWhitelistRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ipStr := r.URL.Query().Get("ip")
	if ipStr == "" {
		http.Error(w, "Missing IP", http.StatusBadRequest)
		return
	}

	removed := s.engine.GetIPFilter().RemoveWhitelist(ipStr)
	if s.fastLog != nil {
		s.fastLog.Info("ADMIN", "Removed from whitelist: %s", ipStr)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"removed": removed,
		"ip":      ipStr,
	})
}

func (s *Server) handleAPIPreset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	preset := r.URL.Query().Get("type")
	udpShield := s.engine.GetUDPShield()
	tcpShield := s.engine.GetTCPShield()

	msg := ""
	switch preset {
	case "HYBRID":

		s.engine.ConfigurePeaceUDP(120, 1048576, 350, 1200, true, true)
		udpShield.SetRateLimits(120, 1048576, 350, 1200)
		udpShield.SetDPI(true)
		if udpShield.GameShield != nil {
			udpShield.GameShield.SetEnabled(true)
		}
		tcpShield.SetMaxConn(100)
		tcpShield.SetStrict(false)
		s.engine.SetGeoIPMode(engine.GeoIPModeAuto)
		s.engine.GetModeManager().SetMode(engine.ModeAuto)
		msg = "Applied Preset: 🌟 Full-Stack Hybrid Shield (Active Game DPI + High-Concurrency Web API)"
	case "GAME":
		s.engine.ConfigurePeaceUDP(120, 1048576, 350, 1200, true, true)
		udpShield.SetRateLimits(120, 1048576, 350, 1200)
		udpShield.SetDPI(true)
		if udpShield.GameShield != nil {
			udpShield.GameShield.SetEnabled(true)
		}
		tcpShield.SetStrict(false)
		s.engine.SetGeoIPMode(engine.GeoIPModeAuto)
		s.engine.GetModeManager().SetMode(engine.ModeAuto)
		msg = "Applied Preset: 🎮 Universal Game Server Shield (120 PPS/Flow, 350 PPS/IP, Query DPI=ON)"
	case "WEB":
		s.engine.ConfigurePeaceUDP(200, 5242880, 500, 2000, false, false)
		udpShield.SetRateLimits(200, 5242880, 500, 2000)
		udpShield.SetDPI(false)
		if udpShield.GameShield != nil {
			udpShield.GameShield.SetEnabled(false)
		}
		tcpShield.SetStrict(false)
		s.engine.SetGeoIPMode(engine.GeoIPModeAuto)
		s.engine.GetModeManager().SetMode(engine.ModeAuto)
		msg = "Applied Preset: 🌐 High-Concurrency Web & API Shield (Stateful SYN limiting, 200 Conns/Subnet)"
	case "STRICT":
		s.engine.GetModeManager().SetMode(engine.ModeOn)
		s.engine.SetGeoIPMode(engine.GeoIPModeOn)
		udpShield.SetRateLimits(35, 524288, 80, 200)
		udpShield.SetDPI(true)
		msg = "Applied Preset: ⚔️ Maximum Lockdown Defense (Strict War Mode + Geo-IP VN Only)"
	default:
		http.Error(w, "Invalid preset", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	s.activePreset = preset
	s.mu.Unlock()

	if s.fastLog != nil {
		s.fastLog.Warn("PRESET", "[SYSTEM] %s (Compiled into Kernel)", msg)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status": "success",
		"preset": preset,
		"msg":    msg,
	})
}

func (s *Server) handleAPIPorts(w http.ResponseWriter, r *http.Request) {
	ports := s.engine.GetDiscovery().GetPorts()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"tcp": ports.TCP,
		"udp": ports.UDP,
	})
}

func (s *Server) handleAPILogs(w http.ResponseWriter, r *http.Request) {
	var events []logger.LogEvent
	if s.fastLog != nil {
		events = s.fastLog.GetRecentEvents(60)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"events": events,
	})
}

func (s *Server) handleAPIMode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	mode := r.URL.Query().Get("mode")
	mm := s.engine.GetModeManager()
	switch mode {
	case "AUTO":
		mm.SetMode(engine.ModeAuto)
	case "WAR":
		mm.SetMode(engine.ModeOn)
	case "PEACE":
		mm.SetMode(engine.ModeOff)
	default:
		http.Error(w, "Invalid mode", http.StatusBadRequest)
		return
	}

	if s.fastLog != nil {
		s.fastLog.Info("ADMIN", "System Defense Mode changed to %s via Web SOC", mode)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status": "success",
		"mode":   string(mm.GetMode()),
	})
}

func (s *Server) handleAPIGeoIP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	mode := r.URL.Query().Get("mode")
	switch mode {
	case "ON":
		s.engine.SetGeoIPMode(engine.GeoIPModeOn)
	case "OFF":
		s.engine.SetGeoIPMode(engine.GeoIPModeOff)
	case "AUTO":
		s.engine.SetGeoIPMode(engine.GeoIPModeAuto)
	default:
		http.Error(w, "Invalid GeoIP mode", http.StatusBadRequest)
		return
	}

	if s.fastLog != nil {
		s.fastLog.Info("ADMIN", "GeoIP Defense Mode set to %s via Web SOC", mode)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status": "success",
		"mode":   mode,
	})
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(embeddedHTML))
}

const embeddedHTML = `<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no, viewport-fit=cover">
    <title>WAF-Shield Enterprise — Cyber Defense Center</title>
    <link rel="icon" type="image/x-icon" href="/favicon.ico">
    <link rel="apple-touch-icon" href="/logo.png">


    <style>
        :root {
            --bg-base: #06090e;
            --bg-card: #0d1527;
            --bg-card-hover: #13203c;
            --border: #1a2a4a;
            --border-highlight: #2a4374;
            --cyan: #00f0ff;
            --cyan-glow: rgba(0, 240, 255, 0.25);
            --green: #10b981;
            --green-glow: rgba(16, 185, 129, 0.25);
            --red: #ef4444;
            --red-glow: rgba(239, 68, 68, 0.25);
            --yellow: #f59e0b;
            --purple: #a855f7;
            --blue: #3b82f6;
            --text-main: #f8fafc;
            --text-dim: #94a3b8;
            --radius: 14px;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; }
        body { background: var(--bg-base); color: var(--text-main); min-height: 100vh; padding-bottom: 50px; overflow-x: hidden; }

        /* Top Cyber Navbar */
        .navbar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: rgba(13, 21, 39, 0.88);
            backdrop-filter: blur(16px);
            padding: 14px 24px;
            border-bottom: 1px solid var(--border);
            position: sticky;
            top: 0;
            z-index: 100;
        }
        .nav-brand { display: flex; align-items: center; gap: 14px; }
        .logo-icon { width: 32px; height: 32px; filter: drop-shadow(0 0 8px var(--cyan)); }
        .nav-logo { font-size: 20px; font-weight: 900; color: #fff; letter-spacing: 0.8px; }
        .nav-logo span { color: var(--cyan); }
        .nav-badge {
            padding: 5px 14px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 0.8px;
            box-shadow: 0 0 10px rgba(0,0,0,0.3);
        }
        .badge-peace { background: rgba(16, 185, 129, 0.15); color: var(--green); border: 1px solid var(--green); box-shadow: 0 0 10px var(--green-glow); }
        .badge-war { background: rgba(239, 68, 68, 0.2); color: var(--red); border: 1px solid var(--red); box-shadow: 0 0 12px var(--red-glow); animation: pulse 1.5s infinite; }
        .badge-elevated { background: rgba(245, 158, 11, 0.15); color: var(--yellow); border: 1px solid var(--yellow); }

        @keyframes pulse { 0%, 100% { opacity: 1; transform: scale(1); } 50% { opacity: 0.65; transform: scale(0.97); } }

        .nav-actions { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }

        /* Main Container */
        .container { max-width: 1380px; margin: 0 auto; padding: 22px 18px; }

        /* Modern Tabs Bar */
        .tabs {
            display: flex;
            gap: 8px;
            background: var(--bg-card);
            padding: 6px;
            border-radius: var(--radius);
            border: 1px solid var(--border);
            margin-bottom: 22px;
            overflow-x: auto;
            scrollbar-width: none;
            -webkit-overflow-scrolling: touch;
        }
        .tabs::-webkit-scrollbar { display: none; }
        .tab-btn {
            background: transparent;
            color: var(--text-dim);
            border: none;
            padding: 11px 20px;
            border-radius: 10px;
            font-size: 13px;
            font-weight: 700;
            cursor: pointer;
            white-space: nowrap;
            transition: all 0.2s ease;
        }
        .tab-btn:hover { color: #fff; background: rgba(255,255,255,0.06); }
        .tab-btn.active { background: var(--blue); color: #fff; box-shadow: 0 0 14px rgba(59, 130, 246, 0.5); }

        /* KPI Cards Grid */
        .grid-kpi {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 22px;
        }
        .card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 18px;
            transition: transform 0.2s, border-color 0.2s, box-shadow 0.2s;
            position: relative;
            overflow: hidden;
        }
        .card:hover { border-color: var(--border-highlight); transform: translateY(-2px); box-shadow: 0 8px 24px rgba(0,0,0,0.4); }
        .card-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }
        .card-title { font-size: 12px; font-weight: 700; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.6px; }
        .card-val { font-size: 24px; font-weight: 900; color: #fff; line-height: 1.2; word-break: break-word; }
        .card-sub { font-size: 12px; color: var(--text-dim); margin-top: 6px; }

        /* 2-Column Responsive Layout */
        .grid-2col {
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 20px;
            margin-bottom: 22px;
        }

        /* Buttons & Actions */
        .btn {
            background: #13203c;
            color: #fff;
            border: 1px solid var(--border-highlight);
            padding: 9px 16px;
            border-radius: 9px;
            font-size: 13px;
            font-weight: 700;
            cursor: pointer;
            transition: all 0.2s;
            touch-action: manipulation;
            display: inline-flex;
            align-items: center;
            gap: 6px;
        }
        .btn:hover { background: #1f335c; }
        .btn.btn-active { box-shadow: 0 0 14px var(--cyan-glow); border-color: var(--cyan); }
        .btn-primary { background: var(--blue); border-color: var(--blue); }
        .btn-primary:hover { background: #2563eb; }
        .btn-danger { background: rgba(239, 68, 68, 0.2); color: var(--red); border-color: var(--red); }
        .btn-danger:hover { background: var(--red); color: #fff; }
        .btn-success { background: rgba(16, 185, 129, 0.2); color: var(--green); border-color: var(--green); }
        .btn-success:hover { background: var(--green); color: #fff; }

        /* Chart Canvas Wrapper */
        .chart-wrapper {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 20px;
            margin-bottom: 22px;
        }
        .chart-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; flex-wrap: wrap; gap: 10px; }
        canvas { width: 100%; height: 180px; border-radius: 10px; display: block; }

        /* Preset Cards */
        .grid-presets {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 16px;
            margin-bottom: 20px;
        }
        .preset-card {
            background: #080e1b;
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 16px;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
        }
        .preset-title { font-size: 15px; font-weight: 800; color: #fff; margin-bottom: 6px; }
        .preset-desc { font-size: 12px; color: var(--text-dim); line-height: 1.5; margin-bottom: 14px; }

        /* Form Inputs */
        .form-row { display: flex; gap: 10px; margin-top: 12px; flex-wrap: wrap; }
        .input-text {
            background: #080c14;
            border: 1px solid var(--border);
            color: #fff;
            padding: 9px 14px;
            border-radius: 8px;
            font-size: 13px;
            outline: none;
            flex: 1;
            min-width: 140px;
        }
        .input-text:focus { border-color: var(--cyan); }

        /* Tables */
        .table-responsive { overflow-x: auto; margin-top: 12px; -webkit-overflow-scrolling: touch; }
        table { width: 100%; border-collapse: collapse; text-align: left; min-width: 480px; }
        th, td { padding: 11px 14px; border-bottom: 1px solid var(--border); font-size: 13px; }
        th { color: var(--text-dim); text-transform: uppercase; font-size: 11px; letter-spacing: 0.6px; }
        tr:hover td { background: rgba(255,255,255,0.025); }

        /* Meters */
        .meter-row { display: flex; justify-content: space-between; margin-bottom: 6px; font-size: 13px; }
        .meter-bar { height: 6px; background: #13203c; border-radius: 3px; overflow: hidden; margin-bottom: 14px; }
        .meter-fill { height: 100%; border-radius: 3px; transition: width 0.3s ease; }

        /* Log Box */
        .log-box {
            background: #04060a;
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 14px;
            max-height: 380px;
            overflow-y: auto;
            font-family: 'Consolas', monospace;
            font-size: 12px;
            line-height: 1.6;
        }
        .log-entry { margin-bottom: 6px; display: flex; gap: 8px; word-break: break-all; }
        .log-time { color: var(--text-dim); min-width: 75px; flex-shrink: 0; }
        .log-cat { font-weight: 800; min-width: 80px; flex-shrink: 0; }

        /* Section View Switcher */
        .tab-content { display: none; }
        .tab-content.active { display: block; }

        /* Mobile Optimization */
        @media (max-width: 768px) {
            .navbar {
                flex-direction: column;
                gap: 12px;
                padding: 12px 14px;
            }
            .nav-brand {
                width: 100%;
                justify-content: space-between;
            }
            .nav-actions {
                width: 100%;
                display: grid;
                grid-template-columns: 1fr 1fr;
                gap: 8px;
            }
            .nav-actions .btn {
                padding: 10px 4px;
                font-size: 12px;
                text-align: center;
                justify-content: center;
                white-space: nowrap;
            }
            .grid-kpi {
                grid-template-columns: repeat(2, 1fr);
                gap: 10px;
            }
            .grid-2col {
                grid-template-columns: 1fr;
                gap: 14px;
            }
            .card {
                padding: 12px;
            }
            .card-val {
                font-size: 18px;
            }
            .card-sub {
                font-size: 11px;
            }
            .container {
                padding: 12px 10px;
            }
            .tabs {
                gap: 4px;
                padding: 4px;
            }
            .tab-btn {
                padding: 9px 13px;
                font-size: 12px;
            }
            canvas {
                height: 150px;
            }
            .log-box {
                font-size: 11px;
                padding: 10px;
            }
            .log-entry {
                flex-direction: column;
                gap: 2px;
                padding-bottom: 6px;
                border-bottom: 1px solid rgba(255,255,255,0.05);
            }
        }
    </style>
</head>
<body>

    <!-- Top Sticky Header -->
    <header class="navbar">
        <div class="nav-brand">
            <!-- 3D Master Cyber Shield Logo -->
            <img src="/logo.png" class="logo-icon" alt="WAF-Shield Logo" style="width:36px; height:36px; border-radius:8px; filter: drop-shadow(0 0 10px rgba(0, 240, 255, 0.7)); object-fit: contain;">
            <div class="nav-logo">WAF-<span>SHIELD</span></div>
            <div id="statusBadge" class="nav-badge badge-peace">[AUTO-PEACE]</div>
        </div>



        <div class="nav-actions">
            <button class="btn btn-primary" id="btnMode" onclick="cycleMode()"> MODE: AUTO</button>
            <button class="btn btn-primary" id="btnGeo" onclick="cycleGeo()"> GEO: AUTO</button>
        </div>
    </header>

    <!-- Main Content Container -->
    <main class="container">

        <!-- Navigation Tabs -->
        <nav class="tabs">
            <button class="tab-btn active" onclick="showTab('tabOverview')">Overview & Traffic</button>
            <button class="tab-btn" onclick="showTab('tabRadar')">Attack Radar</button>
            <button class="tab-btn" onclick="showTab('tabPresets')">Presets & Tuning</button>
            <button class="tab-btn" onclick="showTab('tabBans')">Access Control (Bans / White)</button>
            <button class="tab-btn" onclick="showTab('tabPorts')">Port Inspector</button>
            <button class="tab-btn" onclick="showTab('tabLogs')">Security Logs</button>
        </nav>

        <!-- TAB 1: OVERVIEW & TRAFFIC -->
        <section id="tabOverview" class="tab-content active">
            <div class="grid-kpi">
                <div class="card">
                    <div class="card-header">
                        <span class="card-title">Inbound (RX)</span>
                        <span style="color:var(--yellow); font-size:11px;">▼ IN</span>
                    </div>
                    <div id="valInboundPPS" class="card-val" style="color:var(--yellow);">0 PPS</div>
                    <div id="valInboundBPS" class="card-sub">0 Bps</div>
                </div>

                <div class="card">
                    <div class="card-header">
                        <span class="card-title">Outbound (TX)</span>
                        <span style="color:var(--cyan); font-size:11px;">▲ OUT</span>
                    </div>
                    <div id="valOutboundPPS" class="card-val" style="color:var(--cyan);">0 PPS</div>
                    <div id="valOutboundBPS" class="card-sub">0 Bps</div>
                </div>

                <div class="card">
                    <div class="card-header">
                        <span class="card-title">Passed Clean</span>
                        <span style="color:var(--green); font-size:11px;">✓ PASS</span>
                    </div>
                    <div id="valPassedPPS" class="card-val" style="color:var(--green);">0 PPS</div>
                    <div id="valPassedBPS" class="card-sub">0 Bps</div>
                </div>

                <div class="card">
                    <div class="card-header">
                        <span class="card-title">DDoS Blocked</span>
                        <span style="color:var(--red); font-size:11px;">✕ DROP</span>
                    </div>
                    <div id="valDroppedPPS" class="card-val" style="color:var(--red);">0 PPS</div>
                    <div id="valDroppedBPS" class="card-sub">0 Bps</div>
                </div>

                <div class="card">
                    <div class="card-header">
                        <span class="card-title">Threat Vector</span>
                        <span style="color:var(--yellow); font-size:11px;">▲ RADAR</span>
                    </div>
                    <div id="valThreatVector" class="card-val" style="font-size: 15px; color:var(--yellow);">CLEAN</div>
                    <div id="valThreatDiagnosis" class="card-sub">System normal — 0 active attacks</div>
                </div>
            </div>

            <!-- Real-Time Traffic Wave Chart -->
            <div class="chart-wrapper">
                <div class="chart-header">
                    <h3 style="font-size:15px; font-weight:800;">Bidirectional Real-Time Traffic Pulse (60s History)</h3>
                    <div style="font-size:12px; color:var(--text-dim); display:flex; gap:14px; flex-wrap:wrap;">
                        <span style="color:var(--green); font-weight:700;">■ RX Clean</span>
                        <span style="color:var(--cyan); font-weight:700;">■ TX Outbound</span>
                        <span style="color:var(--red); font-weight:700;">■ Blocked DDoS</span>
                        <span>Uptime: <b id="valUptime" style="color:#fff;">0s</b></span>
                    </div>
                </div>
                <canvas id="trafficCanvas" height="180"></canvas>
            </div>

            <!-- Telemetry Split -->
            <div class="grid-2col">
                <div class="card">
                    <h3 style="margin-bottom:14px; font-size:14px;">Active Session Telemetry</h3>
                    <div class="meter-row"><span>Active UDP Flow Buckets</span><b id="valFlows" style="color:var(--cyan);">0</b></div>
                    <div class="meter-bar"><div id="barFlows" class="meter-fill" style="background:var(--cyan); width:5%;"></div></div>

                    <div class="meter-row"><span>Tracked TCP Sessions</span><b id="valTCP" style="color:var(--green);">0</b></div>
                    <div class="meter-bar"><div id="barTCP" class="meter-fill" style="background:var(--green); width:5%;"></div></div>

                    <div class="meter-row"><span>Quarantined Attackers (Bans)</span><b id="valBansCount" style="color:var(--red);">0</b></div>
                    <div class="meter-bar"><div id="barBans" class="meter-fill" style="background:var(--red); width:0%;"></div></div>
                </div>

                <div class="card">
                    <h3 style="margin-bottom:14px; font-size:14px;">Defense Layers Status</h3>
                    <div style="display:flex; flex-direction:column; gap:10px; font-size:13px;">
                        <div style="display:flex; justify-content:space-between;"><span>Layer 1: Garbage / Reflection Filter</span><b style="color:var(--green);">ACTIVE</b></div>
                        <div style="display:flex; justify-content:space-between;"><span>Layer 2: Socket Discovery (1-65535)</span><b style="color:var(--green);">ACTIVE</b></div>
                        <div style="display:flex; justify-content:space-between;"><span>Layer 3: Stateful SYN / ACK Scrubbing</span><b style="color:var(--green);">ARMED</b></div>
                        <div style="display:flex; justify-content:space-between;"><span>Layer 4: UDP Token Bucket / Subnet /24</span><b style="color:var(--green);">ARMED</b></div>
                        <div style="display:flex; justify-content:space-between;"><span>Geo-IP Filter (Vietnam Binary Tree)</span><b id="valGeoStatus" style="color:var(--yellow);">AUTO</b></div>
                    </div>
                </div>
            </div>
        </section>

        <!-- TAB 2: ATTACK RADAR -->
        <section id="tabRadar" class="tab-content">
            <div class="grid-kpi">
                <div class="card">
                    <div class="card-title">Subnet /24 Carpet Drops</div>
                    <div id="dropSubnet" class="card-val" style="color:var(--yellow);">0</div>
                </div>
                <div class="card">
                    <div class="card-title">UDP Amplification Drops</div>
                    <div id="dropRefl" class="card-val" style="color:var(--purple);">0</div>
                </div>
                <div class="card">
                    <div class="card-title">Game Protocol Query Drops</div>
                    <div id="dropDPI" class="card-val" style="color:var(--blue);">0</div>
                </div>
                <div class="card">
                    <div class="card-title">Out-of-State / ACK Drops</div>
                    <div id="dropOOS" class="card-val" style="color:var(--red);">0</div>
                </div>
                <div class="card" id="botnetCard">
                    <div class="card-header">
                        <div class="card-title">Distributed Botnet Detector</div>
                        <svg width="28" height="28" fill="none" stroke="var(--purple)" stroke-width="1.8" viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="6" r="3"/><circle cx="5" cy="17" r="3"/><circle cx="19" cy="17" r="3"/><path d="M10 8.5L6.5 14M14 8.5l3.5 5.5M8 17h8"/></svg>
                    </div>
                    <div id="valBotnetStatus" class="card-val" style="color:var(--green);">CLEAR</div>
                    <div class="card-sub"><span id="valUniqueIPs">0</span> IP / <span id="valUniqueSubnets">0</span> subnet trong cửa sổ gần nhất</div>
                </div>
                <div class="card">
                    <div class="card-header">
                        <div class="card-title">Behavior Verification Drops</div>
                        <svg width="28" height="28" fill="none" stroke="var(--cyan)" stroke-width="1.8" viewBox="0 0 24 24" aria-hidden="true"><path d="M4 12l5 5L20 6"/><path d="M12 22C6.5 20.5 3 16 3 10V5l9-3 9 3v5c0 6-3.5 10.5-9 12z"/></svg>
                    </div>
                    <div id="dropBehavior" class="card-val" style="color:var(--cyan);">0</div>
                    <div class="card-sub">Two-way + entropy verification</div>
                </div>
            </div>
            <div class="card">
                <h3 style="margin-bottom:12px; font-size:15px;">Active Attack Classification & Strategy</h3>
                <p id="radarDesc" style="color:var(--text-dim); line-height:1.6; font-size:13px;">
                    Bộ phát hiện theo dõi baseline, số IP/subnet duy nhất và tỷ trọng UDP/SYN. Khi có chiến dịch phân tán, hệ thống chuyển War Mode, siết rate-limit, cách ly nguồn lặp lại và xác thực trạng thái giao tiếp.
                </p>
            </div>
        </section>

        <!-- TAB 3: PRESETS & TUNING -->
        <section id="tabPresets" class="tab-content">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:14px; flex-wrap:wrap; gap:10px;">
                <h3 style="font-size:15px; font-weight:800;">1-Click Instant Defense Presets (Chế Độ Phòng Thủ 1 Chạm)</h3>
                <div id="activePresetBadge" class="nav-badge badge-peace" style="font-size:12px;">ACTIVE: 🎮 GAME SHIELD</div>
            </div>
            <div class="grid-presets">
                <div class="preset-card" id="cardPresetHybrid" style="border:1px solid var(--border);">
                    <div>
                        <div class="preset-title" style="display:flex; justify-content:space-between; align-items:center;">
                            <span style="color:var(--yellow);">Full-Stack Hybrid Shield (Cả Game + Web/API)</span>
                            <span id="tagPresetHybrid" class="nav-badge badge-peace" style="display:none; font-size:10px;">ACTIVE</span>
                        </div>
                        <div class="preset-desc">Tối ưu cho VPS chạy <b>cả Game Server (UDP) lẫn Website / REST API (TCP)</b>. Bật Game Query DPI và theo dõi trạng thái TCP với giới hạn SYN theo IP/subnet.</div>
                    </div>
                    <button class="btn btn-primary" id="btnPresetHybrid" onclick="applyPreset('HYBRID')">Kích Hoạt Cả Game & Web</button>
                </div>

                <div class="preset-card" id="cardPresetGame" style="border:2px solid var(--green); box-shadow:0 0 16px var(--green-glow);">
                    <div>
                        <div class="preset-title" style="display:flex; justify-content:space-between; align-items:center;">
                            <span>Universal Game Server Shield</span>
                            <span id="tagPresetGame" class="nav-badge badge-peace" style="font-size:10px;">ACTIVE</span>
                        </div>
                        <div class="preset-desc">Tối ưu chuyên sâu cho Game Server thời gian thực (UDP Realtime). Bật bộ lọc DPI nhận diện chữ ký gói tin, lọc flood truy vấn (Query Spam Filter) và giới hạn 120 PPS/luồng.</div>
                    </div>
                    <button class="btn btn-success btn-active" id="btnPresetGame" onclick="applyPreset('GAME')">✓ ĐANG HOẠT ĐỘNG</button>
                </div>

                <div class="preset-card" id="cardPresetWeb">
                    <div>
                        <div class="preset-title" style="display:flex; justify-content:space-between; align-items:center;">
                            <span>High-Concurrency Web & API Shield</span>
                            <span id="tagPresetWeb" class="nav-badge badge-peace" style="display:none; font-size:10px;">ACTIVE</span>
                        </div>
                        <div class="preset-desc">Tối ưu cho Web Server, REST API và WebSocket. Tăng giới hạn kết nối đồng thời, lọc SYN/ACK sai trạng thái và dọn kết nối treo.</div>
                    </div>
                    <button class="btn btn-primary" id="btnPresetWeb" onclick="applyPreset('WEB')">Kích Hoạt Web Shield</button>
                </div>

                <div class="preset-card" id="cardPresetStrict">
                    <div>
                        <div class="preset-title" style="display:flex; justify-content:space-between; align-items:center;">
                            <span>Maximum Lockdown Defense (Strict War Mode)</span>
                            <span id="tagPresetStrict" class="nav-badge badge-war" style="display:none; font-size:10px;">ACTIVE</span>
                        </div>
                        <div class="preset-desc">Chế độ phòng thủ nghiêm ngặt 24/7. Tự động bật bảo vệ Geo-IP chỉ cho phép Việt Nam và kích hoạt toàn bộ bộ lọc DPI.</div>
                    </div>
                    <button class="btn btn-danger" id="btnPresetStrict" onclick="applyPreset('STRICT')">Khóa Chặt Máy Chủ</button>
                </div>
            </div>
        </section>



        <!-- TAB 4: ACCESS CONTROL -->
        <section id="tabBans" class="tab-content">
            <div class="grid-2col">
                <div class="card">
                    <h3 style="font-size:14px; font-weight:800;">Manual Blacklist Control</h3>
                    <div class="form-row">
                        <input type="text" id="banIP" class="input-text" placeholder="Enter IP (e.g. 1.2.3.4)">
                        <input type="number" id="banDur" class="input-text" style="max-width:90px;" placeholder="Mins" value="15">
                        <button class="btn btn-danger" onclick="manualBan()">Block Host</button>
                    </div>
                    <div class="form-row" style="margin-top:10px;">
                        <input type="text" id="unbanIP" class="input-text" placeholder="Enter IP to unban">
                        <button class="btn btn-success" onclick="manualUnban()">Unblock Host</button>
                    </div>
                </div>
                <div class="card">
                    <h3 style="font-size:14px; font-weight:800;">Manual Whitelist Control</h3>
                    <div class="form-row">
                        <input type="text" id="whiteIP" class="input-text" placeholder="Enter Trusted IP / CIDR">
                        <button class="btn btn-primary" onclick="manualWhitelist()">Always Allow</button>
                    </div>
                </div>
            </div>

            <div class="grid-2col">
                <div class="card">
                    <h3 style="margin-bottom:10px; font-size:14px;">Quarantined Attackers (Blacklist)</h3>
                    <div class="table-responsive">
                        <table>
                            <thead>
                                <tr>
                                    <th>Host / Subnet</th>
                                    <th>Status</th>
                                    <th>Action</th>
                                </tr>
                            </thead>
                            <tbody id="bansTableBody">
                                <tr><td colspan="3" style="color:var(--text-dim);">No active bans.</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>

                <div class="card">
                    <h3 style="margin-bottom:10px; font-size:14px;">Trusted Hosts (Whitelist)</h3>
                    <div class="table-responsive">
                        <table>
                            <thead>
                                <tr>
                                    <th>IP / Subnet</th>
                                    <th>Policy</th>
                                    <th>Action</th>
                                </tr>
                            </thead>
                            <tbody id="whiteTableBody">
                                <tr><td colspan="3" style="color:var(--text-dim);">No custom whitelist rules.</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </section>

        <!-- TAB 5: PORT INSPECTOR -->
        <section id="tabPorts" class="tab-content">
            <div class="card">
                <h3 style="margin-bottom:12px; font-size:14px;">Auto-Discovered System Listening Sockets (1-65535)</h3>
                <div class="table-responsive">
                    <table>
                        <thead>
                            <tr>
                                <th>Port Number</th>
                                <th>Protocol</th>
                                <th>Protection Shield</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody id="portsTableBody">
                            <tr><td colspan="4" style="color:var(--text-dim);">Scanning ports...</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </section>

        <!-- TAB 6: SECURITY LOGS -->
        <section id="tabLogs" class="tab-content">
            <div class="card">
                <div class="chart-header">
                    <h3 style="font-size:14px;">Live Security Audit Stream</h3>
                    <input type="text" id="logSearch" class="input-text" style="max-width:220px;" placeholder="Search logs..." oninput="filterLogs()">
                </div>
                <div class="log-box" id="logContainer">
                    <div style="color:var(--text-dim);">Listening for live security events...</div>
                </div>
            </div>
        </section>

    </main>

    <script>
        function showTab(tabId) {
            document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
            document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
            document.getElementById(tabId).classList.add('active');
            event.target.classList.add('active');
        }

        const maxPoints = 60;
        let cleanHistory = new Array(maxPoints).fill(0);
        let outHistory = new Array(maxPoints).fill(0);
        let dropHistory = new Array(maxPoints).fill(0);
        let rawLogs = [];

        function formatPPS(pps) {
            if (!pps) pps = 0;
            if (pps >= 1000000) return (pps/1000000).toFixed(2) + ' M PPS';
            if (pps >= 1000) return (pps/1000).toFixed(1) + ' K PPS';
            return pps + ' PPS';
        }

        function formatBPS(bps) {
            if (!bps) bps = 0;
            const bits = bps * 8;
            if (bits >= 1073741824) return (bits/1073741824).toFixed(1) + ' Gbps';
            if (bits >= 1048576) return (bits/1048576).toFixed(1) + ' Mbps';
            if (bits >= 1024) return (bits/1024).toFixed(1) + ' Kbps';
            return bits + ' bps';
        }

        function drawChart() {
            const canvas = document.getElementById('trafficCanvas');
            if (!canvas) return;
            const ctx = canvas.getContext('2d');
            const w = canvas.width = canvas.parentElement.clientWidth - 40;
            const h = canvas.height = 180;

            ctx.clearRect(0, 0, w, h);

            let maxVal = Math.max(...cleanHistory, ...outHistory, ...dropHistory, 100);

            ctx.strokeStyle = '#1a2a4a';
            ctx.lineWidth = 1;
            for (let i = 1; i <= 4; i++) {
                let y = h - (h / 4) * i;
                ctx.beginPath();
                ctx.moveTo(0, y);
                ctx.lineTo(w, y);
                ctx.stroke();
            }

            function drawLine(history, strokeColor, fillColor) {
                ctx.beginPath();
                const step = w / (maxPoints - 1);
                for (let i = 0; i < maxPoints; i++) {
                    const x = i * step;
                    const y = h - (history[i] / maxVal) * (h - 20) - 10;
                    if (i === 0) ctx.moveTo(x, y);
                    else ctx.lineTo(x, y);
                }
                ctx.strokeStyle = strokeColor;
                ctx.lineWidth = 2.5;
                ctx.stroke();

                ctx.lineTo(w, h);
                ctx.lineTo(0, h);
                ctx.fillStyle = fillColor;
                ctx.fill();
            }

            drawLine(dropHistory, '#ef4444', 'rgba(239, 68, 68, 0.15)');
            drawLine(outHistory, '#00f0ff', 'rgba(0, 240, 255, 0.12)');
            drawLine(cleanHistory, '#10b981', 'rgba(16, 185, 129, 0.15)');
        }

        async function fetchStats() {
            try {
                const res = await fetch('/api/stats');
                const data = await res.json();

                document.getElementById('valInboundPPS').innerText = formatPPS(data.inbound_pps);
                document.getElementById('valInboundBPS').innerText = formatBPS(data.inbound_bps);
                document.getElementById('valOutboundPPS').innerText = formatPPS(data.outbound_pps);
                document.getElementById('valOutboundBPS').innerText = formatBPS(data.outbound_bps);
                document.getElementById('valPassedPPS').innerText = formatPPS(data.passed_pps);
                document.getElementById('valPassedBPS').innerText = formatBPS(data.passed_bps);
                document.getElementById('valDroppedPPS').innerText = formatPPS(data.dropped_pps);
                document.getElementById('valDroppedBPS').innerText = formatBPS(data.dropped_bps);

                document.getElementById('valThreatVector').innerText = data.primary_vector || 'CLEAN';
                document.getElementById('valThreatDiagnosis').innerText = data.attack_diagnosis || 'System normal';

                document.getElementById('valFlows').innerText = data.active_flows;
                document.getElementById('valTCP').innerText = data.active_tcp;
                document.getElementById('valBansCount').innerText = data.total_bans;
                document.getElementById('valUptime').innerText = data.uptime_sec + 's';
                document.getElementById('valGeoStatus').innerText = data.geoip_mode;

                // Push to Chart History
                cleanHistory.push(data.passed_pps || 0);
                cleanHistory.shift();
                outHistory.push(data.outbound_pps || 0);
                outHistory.shift();
                dropHistory.push(data.dropped_pps || 0);
                dropHistory.shift();
                drawChart();

                // Drops breakdown
                document.getElementById('dropSubnet').innerText = data.drops_subnet;
                document.getElementById('dropRefl').innerText = data.drops_refl;
                document.getElementById('dropDPI').innerText = data.drops_dpi;
                document.getElementById('dropOOS').innerText = data.drops_oos;
                document.getElementById('dropBehavior').innerText = (data.drops_entropy || 0) + (data.drops_unverified || 0);
                document.getElementById('valUniqueIPs').innerText = data.unique_source_ips || 0;
                document.getElementById('valUniqueSubnets').innerText = data.unique_subnets || 0;
                const botnetStatus = document.getElementById('valBotnetStatus');
                botnetStatus.innerText = data.botnet_detected ? 'DETECTED' : 'CLEAR';
                botnetStatus.style.color = data.botnet_detected ? 'var(--red)' : 'var(--green)';

                // Update 2 Header Control Buttons & Status Badge
                currentSysMode = data.system_mode || 'AUTO';
                currentGeoMode = data.geoip_mode || 'AUTO';

                const badge = document.getElementById('statusBadge');
                const btnMode = document.getElementById('btnMode');
                const btnGeo = document.getElementById('btnGeo');

                if (btnMode) {
                    if (currentSysMode === 'ON' || currentSysMode === 'WAR') {
                        btnMode.className = 'btn btn-danger btn-active';
                        btnMode.innerText = 'MODE: WAR';
                        badge.className = 'nav-badge badge-war';
                        badge.innerText = '[WAR-STRICT]';
                    } else if (currentSysMode === 'OFF' || currentSysMode === 'PEACE') {
                        btnMode.className = 'btn btn-success btn-active';
                        btnMode.innerText = 'MODE: PEACE';
                        badge.className = 'nav-badge badge-peace';
                        badge.innerText = '[PEACE-ONLY]';
                    } else {
                        btnMode.className = 'btn btn-primary';
                        btnMode.innerText = 'MODE: AUTO';
                        if (data.threat_mode === 'WAR' || data.threat_mode === 'UNDER_SIEGE') {
                            badge.className = 'nav-badge badge-war';
                            badge.innerText = '[AUTO-WAR]';
                        } else if (data.threat_mode === 'ELEVATED') {
                            badge.className = 'nav-badge badge-elevated';
                            badge.innerText = '[AUTO-ELEVATED]';
                        } else {
                            badge.className = 'nav-badge badge-peace';
                            badge.innerText = '[AUTO-PEACE]';
                        }
                    }
                }

                if (btnGeo) {
                    if (currentGeoMode.includes('ON') || currentGeoMode.includes('VN')) {
                        btnGeo.className = 'btn btn-primary btn-active';
                        btnGeo.innerText = '🌍 GEO: ONLY VN';
                    } else if (currentGeoMode.includes('OFF') || currentGeoMode.includes('World')) {
                        btnGeo.className = 'btn';
                        btnGeo.innerText = '🌍 GEO: OFF';
                    } else {
                        btnGeo.className = 'btn btn-primary';
                        btnGeo.innerText = '🌍 GEO: AUTO';
                    }
                }

                if (data.active_preset) {
                    updatePresetsUI(data.active_preset);
                }

            } catch (e) {}
        }

        function updatePresetsUI(activePreset) {
            const cardHybrid = document.getElementById('cardPresetHybrid');
            const cardGame = document.getElementById('cardPresetGame');
            const cardWeb = document.getElementById('cardPresetWeb');
            const cardStrict = document.getElementById('cardPresetStrict');

            const btnHybrid = document.getElementById('btnPresetHybrid');
            const btnGame = document.getElementById('btnPresetGame');
            const btnWeb = document.getElementById('btnPresetWeb');
            const btnStrict = document.getElementById('btnPresetStrict');

            const tagHybrid = document.getElementById('tagPresetHybrid');
            const tagGame = document.getElementById('tagPresetGame');
            const tagWeb = document.getElementById('tagPresetWeb');
            const tagStrict = document.getElementById('tagPresetStrict');

            const badge = document.getElementById('activePresetBadge');

            // Reset all cards & buttons
            if (cardHybrid) { cardHybrid.style.border = '1px solid var(--border)'; cardHybrid.style.boxShadow = 'none'; }
            if (cardGame) { cardGame.style.border = '1px solid var(--border)'; cardGame.style.boxShadow = 'none'; }
            if (cardWeb) { cardWeb.style.border = '1px solid var(--border)'; cardWeb.style.boxShadow = 'none'; }
            if (cardStrict) { cardStrict.style.border = '1px solid var(--border)'; cardStrict.style.boxShadow = 'none'; }

            if (btnHybrid) { btnHybrid.className = 'btn btn-primary'; btnHybrid.innerText = 'Kích Hoạt Cả Game & Web'; }
            if (btnGame) { btnGame.className = 'btn btn-primary'; btnGame.innerText = 'Kích Hoạt Game Shield'; }
            if (btnWeb) { btnWeb.className = 'btn btn-primary'; btnWeb.innerText = 'Kích Hoạt Web Shield'; }
            if (btnStrict) { btnStrict.className = 'btn btn-danger'; btnStrict.innerText = 'Khóa Chặt Máy Chủ'; }

            if (tagHybrid) tagHybrid.style.display = 'none';
            if (tagGame) tagGame.style.display = 'none';
            if (tagWeb) tagWeb.style.display = 'none';
            if (tagStrict) tagStrict.style.display = 'none';

            if (activePreset === 'HYBRID') {
                if (cardHybrid) { cardHybrid.style.border = '2px solid var(--yellow)'; cardHybrid.style.boxShadow = '0 0 18px rgba(245, 158, 11, 0.4)'; }
                if (btnHybrid) { btnHybrid.className = 'btn btn-success btn-active'; btnHybrid.innerText = '✓ ĐANG BẬT CẢ GAME & WEB'; }
                if (tagHybrid) tagHybrid.style.display = 'inline-block';
                if (badge) { badge.className = 'nav-badge badge-peace'; badge.innerText = 'ACTIVE: 🌟 HYBRID COMBO (GAME + WEB)'; }
            } else if (activePreset === 'GAME') {
                if (cardGame) { cardGame.style.border = '2px solid var(--green)'; cardGame.style.boxShadow = '0 0 18px var(--green-glow)'; }
                if (btnGame) { btnGame.className = 'btn btn-success btn-active'; btnGame.innerText = '✓ ĐANG HOẠT ĐỘNG'; }
                if (tagGame) tagGame.style.display = 'inline-block';
                if (badge) { badge.className = 'nav-badge badge-peace'; badge.innerText = 'ACTIVE: 🎮 GAME SHIELD'; }
            } else if (activePreset === 'WEB') {
                if (cardWeb) { cardWeb.style.border = '2px solid var(--cyan)'; cardWeb.style.boxShadow = '0 0 18px var(--cyan-glow)'; }
                if (btnWeb) { btnWeb.className = 'btn btn-success btn-active'; btnWeb.innerText = '✓ ĐANG HOẠT ĐỘNG'; }
                if (tagWeb) tagWeb.style.display = 'inline-block';
                if (badge) { badge.className = 'nav-badge badge-peace'; badge.innerText = 'ACTIVE: 🌐 WEB SHIELD'; }
            } else if (activePreset === 'STRICT') {
                if (cardStrict) { cardStrict.style.border = '2px solid var(--red)'; cardStrict.style.boxShadow = '0 0 18px var(--red-glow)'; }
                if (btnStrict) { btnStrict.className = 'btn btn-danger btn-active'; btnStrict.innerText = '✓ ĐANG KHÓA CHẶT 24/7'; }
                if (tagStrict) tagStrict.style.display = 'inline-block';
                if (badge) { badge.className = 'nav-badge badge-war'; badge.innerText = 'ACTIVE: ⚔️ STRICT LOCKDOWN'; }
            }
        }


        async function fetchBans() {
            try {
                const res = await fetch('/api/bans');
                const data = await res.json();
                const tbody = document.getElementById('bansTableBody');
                if (!data.bans || data.bans.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="3" style="color:var(--text-dim);">No active bans. (Clean State)</td></tr>';
                    return;
                }
                tbody.innerHTML = data.bans.map(b => {
                    const cleanIP = b.replace(/\[BAN\]\s*/i, '').trim();
                    return '<tr>' +
                        '<td><b style="color:var(--red);">' + b + '</b></td>' +
                        '<td><span class="nav-badge badge-war">BANNED</span></td>' +
                        '<td><button class="btn btn-success" style="padding:4px 10px; font-size:11px;" onclick="unbanSpecific(\'' + cleanIP + '\')">Unblock</button></td>' +
                    '</tr>';
                }).join('');
            } catch (e) {}
        }

        async function fetchWhitelist() {
            try {
                const res = await fetch('/api/whitelist');
                const data = await res.json();
                const tbody = document.getElementById('whiteTableBody');
                if (!data.whitelist || data.whitelist.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="3" style="color:var(--text-dim);">No custom whitelist entries.</td></tr>';
                    return;
                }
                tbody.innerHTML = data.whitelist.map(ip => {
                    return '<tr>' +
                        '<td><b style="color:var(--green);">' + ip + '</b></td>' +
                        '<td><span class="nav-badge badge-peace">ALWAYS PASS</span></td>' +
                        '<td><button class="btn btn-danger" style="padding:4px 10px; font-size:11px;" onclick="removeWhitelist(\'' + ip + '\')">Remove</button></td>' +
                    '</tr>';
                }).join('');
            } catch (e) {}
        }

        async function removeWhitelist(ip) {
            await fetch('/api/whitelist/remove?ip=' + ip, { method: 'POST' });
            fetchWhitelist();
        }

        async function applyPreset(type) {
            try {
                updatePresetsUI(type);
                const res = await fetch('/api/preset?type=' + type, { method: 'POST' });
                const data = await res.json();
                fetchStats();
                fetchLogs();
                alert(data.msg || 'Preset applied!');
            } catch (e) {
                alert('Lỗi kết nối máy chủ khi áp dụng Preset');
            }
        }


        async function fetchPorts() {
            try {
                const res = await fetch('/api/ports');
                const data = await res.json();
                const tbody = document.getElementById('portsTableBody');
                let rows = [];

                if (data.tcp) {
                    Object.keys(data.tcp).forEach(p => {
                        rows.push('<tr>' +
                            '<td><b style="color:#fff;">Port ' + p + '</b></td>' +
                            '<td><span style="color:var(--blue); font-weight:700;">TCP</span></td>' +
                            '<td>Stateful SYN/ACK tracking + Token Bucket</td>' +
                            '<td><span class="nav-badge badge-peace">PROTECTED</span></td>' +
                        '</tr>');
                    });
                }
                if (data.udp) {
                    Object.keys(data.udp).forEach(p => {
                        rows.push('<tr>' +
                            '<td><b style="color:#fff;">Port ' + p + '</b></td>' +
                            '<td><span style="color:var(--purple); font-weight:700;">UDP</span></td>' +
                            '<td>Two-Way Verify + Game DPI</td>' +
                            '<td><span class="nav-badge badge-peace">PROTECTED</span></td>' +
                        '</tr>');
                    });
                }

                if (rows.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="4" style="color:var(--text-dim);">No listening ports detected yet.</td></tr>';
                } else {
                    tbody.innerHTML = rows.join('');
                }
            } catch (e) {}
        }

        async function fetchLogs() {
            try {
                const res = await fetch('/api/logs');
                const data = await res.json();
                if (data.events) {
                    rawLogs = data.events;
                    renderLogs(rawLogs);
                }
            } catch (e) {}
        }

        function renderLogs(events) {
            const container = document.getElementById('logContainer');
            if (!events || events.length === 0) {
                container.innerHTML = '<div style="color:var(--text-dim);">No log entries recorded.</div>';
                return;
            }
            container.innerHTML = events.map(ev => {
                const color = ev.Level === 2 ? 'var(--red)' : (ev.Level === 3 ? 'var(--yellow)' : 'var(--cyan)');
                const timeStr = ev.Timestamp ? new Date(ev.Timestamp).toLocaleTimeString() : '--:--:--';
                return '<div class="log-entry">' +
                    '<span class="log-time">' + timeStr + '</span>' +
                    '<span class="log-cat" style="color:' + color + '">[' + ev.Category + ']</span>' +
                    '<span>' + ev.Message + '</span>' +
                '</div>';
            }).join('');
        }

        function filterLogs() {
            const q = document.getElementById('logSearch').value.toLowerCase();
            const filtered = rawLogs.filter(ev => 
                ev.Category.toLowerCase().includes(q) || ev.Message.toLowerCase().includes(q)
            );
            renderLogs(filtered);
        }

        let currentSysMode = 'AUTO';
        let currentGeoMode = 'AUTO';

        async function cycleMode() {
            let nextMode = 'AUTO';
            if (currentSysMode === 'AUTO') nextMode = 'WAR';
            else if (currentSysMode === 'WAR' || currentSysMode === 'ON') nextMode = 'PEACE';
            else nextMode = 'AUTO';

            await fetch('/api/mode?mode=' + nextMode, { method: 'POST' });
            setTimeout(fetchStats, 100);
        }

        async function cycleGeo() {
            let nextGeo = 'AUTO';
            if (currentGeoMode === 'AUTO') nextGeo = 'ON';
            else if (currentGeoMode === 'ON' || currentGeoMode.includes('ON') || currentGeoMode.includes('VN')) nextGeo = 'OFF';
            else nextGeo = 'AUTO';

            await fetch('/api/geoip?mode=' + nextGeo, { method: 'POST' });
            setTimeout(fetchStats, 100);
        }

        async function manualBan() {
            const ip = document.getElementById('banIP').value.trim();
            const dur = document.getElementById('banDur').value.trim();
            if (!ip) return alert('Please enter an IP');
            await fetch('/api/ban?ip=' + ip + '&dur=' + dur, { method: 'POST' });
            document.getElementById('banIP').value = '';
            fetchBans();
            fetchStats();
        }

        async function manualUnban() {
            const ip = document.getElementById('unbanIP').value.trim();
            if (!ip) return alert('Please enter an IP');
            await fetch('/api/unban?ip=' + ip, { method: 'POST' });
            document.getElementById('unbanIP').value = '';
            fetchBans();
            fetchStats();
        }

        async function unbanSpecific(ip) {
            await fetch('/api/unban?ip=' + ip, { method: 'POST' });
            fetchBans();
            fetchStats();
        }

        async function manualWhitelist() {
            const ip = document.getElementById('whiteIP').value.trim();
            if (!ip) return alert('Please enter an IP');
            await fetch('/api/whitelist?ip=' + ip, { method: 'POST' });
            document.getElementById('whiteIP').value = '';
            fetchWhitelist();
            alert('Whitelisted ' + ip);
        }

        window.addEventListener('resize', drawChart);

        setInterval(fetchStats, 1000);
        setInterval(fetchBans, 3000);
        setInterval(fetchWhitelist, 5000);
        setInterval(fetchLogs, 2000);
        setInterval(fetchPorts, 5000);

        fetchStats();
        fetchBans();
        fetchWhitelist();
        fetchLogs();
        fetchPorts();
    </script>
</body>
</html>`
