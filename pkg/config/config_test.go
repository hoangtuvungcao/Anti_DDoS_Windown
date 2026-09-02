package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Workers != 0 {
		t.Errorf("Expected default workers 0 (auto-detect), got %d", cfg.Workers)
	}
	if cfg.PeaceMode.UDPPPSPerFlow != 120 {
		t.Errorf("Expected UDP PPS flow limit 120, got %v", cfg.PeaceMode.UDPPPSPerFlow)
	}
	if cfg.WarMode.TriggerPPS != 4000 {
		t.Errorf("Expected War trigger PPS 4000, got %d", cfg.WarMode.TriggerPPS)
	}
	if cfg.WebDashboard.AllowLAN {
		t.Error("production default must keep dashboard on localhost")
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

	if cfg.Workers != 0 {
		t.Errorf("Expected default workers 0, got %d", cfg.Workers)
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

func TestLoad_WithVietnameseComments(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config_commented.json")

	content := `{
		// Số luồng CPU tự động
		"workers": 0,
		/* Chế độ bảo vệ tự động
		   Có thể chọn AUTO, WAR hoặc PEACE */
		"system_mode": "AUTO",
		"peace_mode": {
			// Giới hạn PPS cho mỗi luồng
			"udp_pps_per_flow": 120.0,
			"udp_bps_per_flow": 1048576.0
		},
		"whitelist_ips": [
			// IP localhost
			"127.0.0.1"
		]
	}`

	err := os.WriteFile(configPath, []byte(content), 0644)
	if err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config with comments: %v", err)
	}

	if cfg.SystemMode != "AUTO" {
		t.Errorf("Expected SystemMode AUTO, got %s", cfg.SystemMode)
	}
	if cfg.PeaceMode.UDPPPSPerFlow != 120.0 {
		t.Errorf("Expected UDPPPSPerFlow 120, got %v", cfg.PeaceMode.UDPPPSPerFlow)
	}
}

func TestValidateRejectsUnauthenticatedLANDashboard(t *testing.T) {
	cfg := DefaultConfig()
	cfg.WebDashboard.AllowLAN = true
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected unsafe LAN dashboard configuration to be rejected")
	}
	cfg.WebDashboard.Username = "admin"
	cfg.WebDashboard.Password = "a-unique-password-2026"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected authenticated LAN dashboard to validate: %v", err)
	}
}
