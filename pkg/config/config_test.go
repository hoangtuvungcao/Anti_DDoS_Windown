package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Workers != 2 {
		t.Errorf("Expected default workers 2, got %d", cfg.Workers)
	}
	if cfg.PeaceMode.UDPPPSPerFlow != 150 {
		t.Errorf("Expected UDP PPS flow limit 150, got %v", cfg.PeaceMode.UDPPPSPerFlow)
	}
	if cfg.WarMode.TriggerPPS != 50000 {
		t.Errorf("Expected War trigger PPS 50000, got %d", cfg.WarMode.TriggerPPS)
	}
}

func TestLoadAndSave(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "waf-config-test")
	if err != nil {
		t.Fatalf("Failed to create tmp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	configPath := filepath.Join(tmpDir, "config.json")

	// 1. Loading non-existent file should create and return default config
	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if cfg.Workers != 2 {
		t.Errorf("Expected default workers 2, got %d", cfg.Workers)
	}

	// Verify file was actually created
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Errorf("Config file was not created on load")
	}

	// 2. Modify and Save config
	cfg.Workers = 4
	cfg.PeaceMode.UDPPPSPerFlow = 300
	err = Save(configPath, cfg)
	if err != nil {
		t.Fatalf("Failed to save config: %v", err)
	}

	// 3. Re-load and verify modifications
	cfg2, err := Load(configPath)
	if err != nil {
		t.Fatalf("Failed to reload config: %v", err)
	}

	if cfg2.Workers != 4 {
		t.Errorf("Expected workers 4, got %d", cfg2.Workers)
	}
	if cfg2.PeaceMode.UDPPPSPerFlow != 300 {
		t.Errorf("Expected UDP PPS flow limit 300, got %v", cfg2.PeaceMode.UDPPPSPerFlow)
	}
}

func TestToEngineConfig(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Discovery.ExcludePorts = []uint16{80, 443}

	engCfg := cfg.ToEngineConfig()

	if engCfg.Workers != cfg.Workers {
		t.Errorf("Workers mismatch")
	}
	if engCfg.UDPFlowPPS != cfg.PeaceMode.UDPPPSPerFlow {
		t.Errorf("UDP flow PPS mismatch")
	}
	if engCfg.BlacklistDur != time.Duration(cfg.PeaceMode.BlacklistDurSec)*time.Second {
		t.Errorf("Blacklist duration mismatch")
	}
	if len(engCfg.ExcludePorts) != 2 || engCfg.ExcludePorts[0] != 80 || engCfg.ExcludePorts[1] != 443 {
		t.Errorf("Exclude ports mismatch: %v", engCfg.ExcludePorts)
	}
}
