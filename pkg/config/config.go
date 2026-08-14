package config

import (
	"encoding/json"
	"os"
	"time"

	"waf-game/pkg/engine"
)

// Config represents the JSON configuration file structure.
type Config struct {
	Workers    int    `json:"workers"`
	LogFile    string `json:"log_file"`
	SystemMode string `json:"system_mode"`

	PeaceMode PeaceModeConfig `json:"peace_mode"`
	WarMode   WarModeConfig   `json:"war_mode"`
	Cache     CacheConfig     `json:"cache"`
	Discovery DiscoveryConfig `json:"discovery"`

	CustomRules  []CustomRule `json:"custom_rules"`
	WhitelistIPs []string     `json:"whitelist_ips"`
	BlacklistIPs []string     `json:"blacklist_ips"`

	WebDashboard  WebDashboardConfig  `json:"web_dashboard"`
	Notifications NotificationsConfig `json:"notifications"`
}

// WebDashboardConfig settings
type WebDashboardConfig struct {
	Enabled  bool   `json:"enabled"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	AllowLAN bool   `json:"allow_lan"`
}

// NotificationsConfig settings
type NotificationsConfig struct {
	Enabled           bool   `json:"enabled"`
	DiscordWebhookURL string `json:"discord_webhook_url"`
	TelegramBotToken  string `json:"telegram_bot_token"`
	TelegramChatID    string `json:"telegram_chat_id"`
	CooldownSec       int    `json:"cooldown_sec"`
}


// PeaceModeConfig holds normal operation settings
type PeaceModeConfig struct {
	UDPPPSPerFlow             float64 `json:"udp_pps_per_flow"`
	UDPBPSPerFlow             float64 `json:"udp_bps_per_flow"`
	UDPPPSPerIP               float64 `json:"udp_pps_per_ip"`
	SubnetPPSLimit            float64 `json:"subnet_pps_limit"`
	BlacklistDurSec           int     `json:"blacklist_duration_sec"`
	TCPMaxConnPerIP           int32   `json:"tcp_max_conn_per_ip"`
	TCPConnRatePerIP          int32   `json:"tcp_conn_rate_per_ip"`
	TCPMaxConnPerSubnet       int32   `json:"tcp_max_conn_per_subnet"`
	TCPIdleTimeoutSec         int64   `json:"tcp_idle_timeout_sec"`
	EnableAmplificationFilter bool    `json:"enable_amplification_filter"`
	EnableDPIShield           bool    `json:"enable_dpi_shield"`
	EnableGameShield          bool    `json:"enable_game_shield,omitempty"`
}

// WarModeConfig holds attack-mode settings
type WarModeConfig struct {
	TriggerPPS      uint64  `json:"trigger_pps"`
	TriggerBPS      uint64  `json:"trigger_bps"`
	CooldownSec     int64   `json:"cooldown_sec"`
	UDPPPSPerFlow   float64 `json:"udp_pps_per_flow"`
	UDPPerIPPPS     float64 `json:"udp_pps_per_ip"`
	SubnetPPSLimit  float64 `json:"subnet_pps_limit"`
	EnableDPI       bool    `json:"enable_dpi"`
	EntropyMode     string  `json:"entropy_mode"`
	EnableTwoWay    bool    `json:"enable_twoway"`
	GeoIPMode       string  `json:"geoip_mode"`
	StrictWhitelist bool    `json:"strict_whitelist"`
}

// CacheConfig holds memory management settings
type CacheConfig struct {
	MaxEntries       int `json:"max_entries"`
	TTLSec           int `json:"ttl_sec"`
	SweepIntervalSec int `json:"sweep_interval_sec"`
	Shards           int `json:"shards"`
}

// DiscoveryConfig holds port scanning settings
type DiscoveryConfig struct {
	IntervalSec  int      `json:"interval_sec"`
	ExcludePorts []uint16 `json:"exclude_ports"`
}

// CustomRule defines an optional custom signature rule for a specific port
type CustomRule struct {
	Port         uint16 `json:"port"`
	Protocol     string `json:"protocol"`
	Name         string `json:"name,omitempty"`
	SignatureHex string `json:"signature_hex,omitempty"`
	AllowPPS     int    `json:"allow_pps"`
}

// GameRule alias for backward compatibility
type GameRule = CustomRule


// DefaultConfig returns a config with sensible defaults for high-protection
func DefaultConfig() Config {
	return Config{
		Workers:    0, // 0 = Auto-detect CPU cores
		LogFile:    "resources/logs/shield.log",
		SystemMode: "AUTO",
		PeaceMode: PeaceModeConfig{
			UDPPPSPerFlow:             120,
			UDPBPSPerFlow:             1048576, // 1 MB/s
			UDPPPSPerIP:               350,
			SubnetPPSLimit:            1200,
			BlacklistDurSec:           300,
			TCPMaxConnPerIP:           60,
			TCPConnRatePerIP:          25,
			TCPMaxConnPerSubnet:       300,
			TCPIdleTimeoutSec:         90,
			EnableAmplificationFilter: true,
			EnableGameShield:          true,
		},

		WarMode: WarModeConfig{
			TriggerPPS:      4000,     // Reacts in <0.5s to any sudden spike
			TriggerBPS:      31457280, // 30 MB/s
			CooldownSec:     60,
			UDPPPSPerFlow:   35,
			UDPPerIPPPS:     80,
			SubnetPPSLimit:  200,
			EnableDPI:       true,
			EntropyMode:     "AUTO",
			EnableTwoWay:    true,
			GeoIPMode:       "AUTO",
			StrictWhitelist: true,
		},

		Cache: CacheConfig{
			MaxEntries:       300000,
			TTLSec:           30,
			SweepIntervalSec: 10,
			Shards:           64,
		},
		Discovery: DiscoveryConfig{
			IntervalSec:  5,
			ExcludePorts: []uint16{},
		},
		CustomRules:  []CustomRule{},
		WhitelistIPs: []string{"127.0.0.1"},
		BlacklistIPs: []string{},
		WebDashboard: WebDashboardConfig{
			Enabled:  true,
			Port:     8080,
			Username: "",
			Password: "",
			AllowLAN: true,
		},
		Notifications: NotificationsConfig{
			Enabled:           false,
			DiscordWebhookURL: "",
			TelegramBotToken:  "",
			TelegramChatID:    "",
			CooldownSec:       30,
		},
	}
}



// Load reads config from file with full support for JavaScript/C-style comments (// and /* */).
// If file doesn't exist, creates it with defaults.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			cfg := DefaultConfig()
			if err := Save(path, &cfg); err != nil {
				return nil, err
			}
			return &cfg, nil
		}
		return nil, err
	}

	cleanData := stripJSONComments(data)

	var cfg Config
	if err := json.Unmarshal(cleanData, &cfg); err != nil {
		return nil, err
	}


	// Fill zero values with defaults
	def := DefaultConfig()
	if cfg.PeaceMode.UDPPPSPerFlow == 0 {
		cfg.PeaceMode.UDPPPSPerFlow = def.PeaceMode.UDPPPSPerFlow
	}
	if cfg.PeaceMode.UDPBPSPerFlow == 0 {
		cfg.PeaceMode.UDPBPSPerFlow = def.PeaceMode.UDPBPSPerFlow
	}
	if cfg.PeaceMode.UDPPPSPerIP == 0 {
		cfg.PeaceMode.UDPPPSPerIP = def.PeaceMode.UDPPPSPerIP
	}
	if cfg.PeaceMode.SubnetPPSLimit == 0 {
		cfg.PeaceMode.SubnetPPSLimit = def.PeaceMode.SubnetPPSLimit
	}
	if cfg.PeaceMode.TCPMaxConnPerIP == 0 {
		cfg.PeaceMode.TCPMaxConnPerIP = def.PeaceMode.TCPMaxConnPerIP
	}
	if cfg.PeaceMode.TCPConnRatePerIP == 0 {
		cfg.PeaceMode.TCPConnRatePerIP = def.PeaceMode.TCPConnRatePerIP
	}
	if cfg.PeaceMode.TCPMaxConnPerSubnet == 0 {
		cfg.PeaceMode.TCPMaxConnPerSubnet = def.PeaceMode.TCPMaxConnPerSubnet
	}
	if cfg.PeaceMode.TCPIdleTimeoutSec == 0 {
		cfg.PeaceMode.TCPIdleTimeoutSec = def.PeaceMode.TCPIdleTimeoutSec
	}
	if cfg.WarMode.TriggerPPS == 0 {
		cfg.WarMode.TriggerPPS = def.WarMode.TriggerPPS
	}
	if cfg.WarMode.TriggerBPS == 0 {
		cfg.WarMode.TriggerBPS = def.WarMode.TriggerBPS
	}
	if cfg.WarMode.UDPPPSPerFlow == 0 {
		cfg.WarMode.UDPPPSPerFlow = def.WarMode.UDPPPSPerFlow
	}
	if cfg.WarMode.UDPPerIPPPS == 0 {
		cfg.WarMode.UDPPerIPPPS = def.WarMode.UDPPerIPPPS
	}
	if cfg.WarMode.SubnetPPSLimit == 0 {
		cfg.WarMode.SubnetPPSLimit = def.WarMode.SubnetPPSLimit
	}
	if cfg.WarMode.GeoIPMode == "" {
		cfg.WarMode.GeoIPMode = "AUTO"
	}
	if cfg.WarMode.EntropyMode == "" {
		cfg.WarMode.EntropyMode = "AUTO"
	}
	if cfg.Cache.MaxEntries == 0 {
		cfg.Cache = def.Cache
	}
	if cfg.Discovery.IntervalSec == 0 {
		cfg.Discovery = def.Discovery
	}
	if cfg.SystemMode == "" {
		cfg.SystemMode = "AUTO"
	}

	return &cfg, nil
}

// Save writes config to file with pretty formatting.
func Save(path string, cfg *Config) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// ToEngineConfig converts Config to engine.EngineConfig
func (c *Config) ToEngineConfig() engine.EngineConfig {
	excludePorts := make([]uint16, len(c.Discovery.ExcludePorts))
	copy(excludePorts, c.Discovery.ExcludePorts)

	geoIPMode := engine.GeoIPModeAuto
	switch c.WarMode.GeoIPMode {
	case "ON", "on", "On":
		geoIPMode = engine.GeoIPModeOn
	case "OFF", "off", "Off":
		geoIPMode = engine.GeoIPModeOff
	}

	entropyMode := engine.EntropyModeAuto
	switch c.WarMode.EntropyMode {
	case "ON", "on", "On":
		entropyMode = engine.EntropyModeOn
	case "OFF", "off", "Off":
		entropyMode = engine.EntropyModeOff
	}

	rules := c.CustomRules
	convertedRules := make([]engine.CustomGameRule, len(rules))
	for i, r := range rules {
		convertedRules[i] = engine.CustomGameRule{
			Port:         r.Port,
			Protocol:     r.Protocol,
			Game:         r.Name,
			SignatureHex: r.SignatureHex,
			AllowPPS:     r.AllowPPS,
		}
	}


	enableDPI := c.PeaceMode.EnableDPIShield || c.PeaceMode.EnableGameShield

	return engine.EngineConfig{
		Workers:                   c.Workers,
		DiscoveryInterval:         time.Duration(c.Discovery.IntervalSec) * time.Second,
		ExcludePorts:              excludePorts,
		UDPFlowPPS:                c.PeaceMode.UDPPPSPerFlow,
		UDPFlowBPS:                c.PeaceMode.UDPBPSPerFlow,
		UDPPerIPPPS:               c.PeaceMode.UDPPPSPerIP,
		SubnetPPS:                 c.PeaceMode.SubnetPPSLimit,
		BlacklistDur:              time.Duration(c.PeaceMode.BlacklistDurSec) * time.Second,
		TCPMaxConnIP:              c.PeaceMode.TCPMaxConnPerIP,
		TCPConnRateIP:             c.PeaceMode.TCPConnRatePerIP,
		TCPMaxConnSubnet:          c.PeaceMode.TCPMaxConnPerSubnet,
		TCPIdleTimeout:            c.PeaceMode.TCPIdleTimeoutSec,
		EnableAmplificationFilter: c.PeaceMode.EnableAmplificationFilter,
		EnableGameShield:          enableDPI,
		WarTriggerPPS:             c.WarMode.TriggerPPS,
		WarTriggerBPS:             c.WarMode.TriggerBPS,
		WarCooldown:               c.WarMode.CooldownSec,
		WarFlowPPS:                c.WarMode.UDPPPSPerFlow,
		WarIPPPS:                  c.WarMode.UDPPerIPPPS,
		WarSubnetPPS:              c.WarMode.SubnetPPSLimit,
		EntropyMode:               entropyMode,
		GeoIPMode:                 geoIPMode,
		SystemMode:                c.SystemMode,
		WhitelistIPs:              c.WhitelistIPs,
		BlacklistIPs:              c.BlacklistIPs,
		GameRules:                 convertedRules,
	}
}

// stripJSONComments removes single-line (//) and multi-line (/* */) comments from JSON data
// while safely preserving string literals.
func stripJSONComments(data []byte) []byte {
	out := make([]byte, 0, len(data))
	inString := false
	escaped := false
	n := len(data)

	for i := 0; i < n; i++ {
		b := data[i]

		if inString {
			out = append(out, b)
			if escaped {
				escaped = false
			} else if b == '\\' {
				escaped = true
			} else if b == '"' {
				inString = false
			}
			continue
		}

		if b == '"' {
			inString = true
			out = append(out, b)
			continue
		}

		// Check single-line comment //
		if b == '/' && i+1 < n && data[i+1] == '/' {
			i += 2
			for i < n && data[i] != '\n' && data[i] != '\r' {
				i++
			}
			if i < n {
				out = append(out, data[i])
			}
			continue
		}

		// Check multi-line comment /* ... */
		if b == '/' && i+1 < n && data[i+1] == '*' {
			i += 2
			for i+1 < n && !(data[i] == '*' && data[i+1] == '/') {
				if data[i] == '\n' {
					out = append(out, '\n')
				}
				i++
			}
			i++ // Skip closing '/'
			continue
		}

		out = append(out, b)
	}

	return out
}



