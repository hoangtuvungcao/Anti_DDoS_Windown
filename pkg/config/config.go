package config

import (
	"encoding/json"
	"os"
	"time"

	"waf-game/pkg/engine"
)

// Config represents the JSON configuration file structure.
type Config struct {
	Workers int    `json:"workers"`
	LogFile string `json:"log_file"`
	SystemMode string `json:"system_mode"`

	PeaceMode PeaceModeConfig `json:"peace_mode"`
	WarMode   WarModeConfig   `json:"war_mode"`
	Cache     CacheConfig     `json:"cache"`
	Discovery DiscoveryConfig `json:"discovery"`

	GameRules    []GameRule `json:"game_rules"`
	WhitelistIPs []string  `json:"whitelist_ips"`
	BlacklistIPs []string  `json:"blacklist_ips"`
}

// PeaceModeConfig holds normal operation settings
type PeaceModeConfig struct {
	UDPPPSPerFlow    float64 `json:"udp_pps_per_flow"`
	UDPBPSPerFlow    float64 `json:"udp_bps_per_flow"`
	UDPPPSPerIP      float64 `json:"udp_pps_per_ip"`
	BlacklistDurSec  int     `json:"blacklist_duration_sec"`
	TCPMaxConnPerIP  int32   `json:"tcp_max_conn_per_ip"`
	TCPIdleTimeoutSec int64  `json:"tcp_idle_timeout_sec"`
}

// WarModeConfig holds attack-mode settings
type WarModeConfig struct {
	TriggerPPS      uint64  `json:"trigger_pps"`
	TriggerBPS      uint64  `json:"trigger_bps"`
	CooldownSec     int64   `json:"cooldown_sec"`
	UDPPPSPerFlow   float64 `json:"udp_pps_per_flow"`
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

// GameRule defines a manual protection rule for a specific port
type GameRule struct {
	Port         uint16 `json:"port"`
	Protocol     string `json:"protocol"`
	Game         string `json:"game"`
	SignatureHex string `json:"signature_hex,omitempty"`
	AllowPPS     int    `json:"allow_pps"`
}

// DefaultConfig returns a config with sensible defaults
func DefaultConfig() Config {
	return Config{
		Workers: 2,
		LogFile: "shield.log",
		SystemMode: "AUTO",
		PeaceMode: PeaceModeConfig{
			UDPPPSPerFlow:     150,
			UDPBPSPerFlow:     1048576,
			UDPPPSPerIP:       500,
			BlacklistDurSec:   300,
			TCPMaxConnPerIP:   100,
			TCPIdleTimeoutSec: 5,
		},
		WarMode: WarModeConfig{
			TriggerPPS:      50000,
			TriggerBPS:      209715200,
			CooldownSec:     60,
			UDPPPSPerFlow:   100,
			EnableDPI:       true,
			EntropyMode:     "AUTO",
			EnableTwoWay:    true,
			GeoIPMode:       "AUTO",
			StrictWhitelist: true,
		},
		Cache: CacheConfig{
			MaxEntries:       200000,
			TTLSec:           30,
			SweepIntervalSec: 10,
			Shards:           64,
		},
		Discovery: DiscoveryConfig{
			IntervalSec:  5,
			ExcludePorts: []uint16{},
		},
		GameRules:    []GameRule{},
		WhitelistIPs: []string{},
		BlacklistIPs: []string{},
	}
}

// Load reads config from file. If file doesn't exist, creates it with defaults.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// Create default config
			cfg := DefaultConfig()
			if err := Save(path, &cfg); err != nil {
				return nil, err
			}
			return &cfg, nil
		}
		return nil, err
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	// Fill zero values with defaults
	def := DefaultConfig()
	if cfg.Workers == 0 {
		cfg.Workers = def.Workers
	}
	if cfg.PeaceMode.UDPPPSPerFlow == 0 {
		cfg.PeaceMode = def.PeaceMode
	}
	if cfg.WarMode.TriggerPPS == 0 {
		cfg.WarMode = def.WarMode
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

	return engine.EngineConfig{
		Workers:           c.Workers,
		DiscoveryInterval: time.Duration(c.Discovery.IntervalSec) * time.Second,
		ExcludePorts:      excludePorts,
		UDPFlowPPS:        c.PeaceMode.UDPPPSPerFlow,
		UDPFlowBPS:        c.PeaceMode.UDPBPSPerFlow,
		UDPPerIPPPS:       c.PeaceMode.UDPPPSPerIP,
		BlacklistDur:      time.Duration(c.PeaceMode.BlacklistDurSec) * time.Second,
		TCPMaxConnIP:      c.PeaceMode.TCPMaxConnPerIP,
		TCPIdleTimeout:    c.PeaceMode.TCPIdleTimeoutSec,
		WarTriggerPPS:     c.WarMode.TriggerPPS,
		WarTriggerBPS:     c.WarMode.TriggerBPS,
		WarCooldown:       c.WarMode.CooldownSec,
		WarFlowPPS:        c.WarMode.UDPPPSPerFlow,
		EntropyMode:       entropyMode,
		GeoIPMode:         geoIPMode,
		SystemMode:        c.SystemMode,
	}
}
