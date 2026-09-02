package web

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"waf-game/pkg/config"
	"waf-game/pkg/engine"
	"waf-game/pkg/stats"
)

func TestWebServer_APIEndpoints(t *testing.T) {
	metrics := stats.NewMetrics()
	cfg := config.DefaultConfig()
	eng, err := engine.NewEngine(cfg.ToEngineConfig(), metrics, nil)
	if err != nil {
		// Mock test without driver
		t.Skip("Skipping engine dependent test without driver")
	}
	defer eng.Stop()

	webCfg := WebConfig{
		Enabled:  true,
		Port:     18080,
		AllowLAN: false,
	}

	srv := NewServer(webCfg, eng, metrics, nil)

	// Test /api/stats
	req := httptest.NewRequest(http.MethodGet, "/api/stats", nil)
	w := httptest.NewRecorder()
	srv.handleAPIStats(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected HTTP 200, got %d", w.Code)
	}

	// Test /
	reqHome := httptest.NewRequest(http.MethodGet, "/", nil)
	wHome := httptest.NewRecorder()
	srv.handleDashboard(wHome, reqHome)

	if wHome.Code != http.StatusOK {
		t.Errorf("Expected HTTP 200 for dashboard, got %d", wHome.Code)
	}
}

func TestStartRejectsUnauthenticatedLANBinding(t *testing.T) {
	srv := NewServer(WebConfig{Enabled: true, Port: 18081, AllowLAN: true}, nil, nil, nil)
	if err := srv.Start(); err == nil {
		srv.Stop()
		t.Fatal("expected unauthenticated LAN binding to be rejected")
	}
}
