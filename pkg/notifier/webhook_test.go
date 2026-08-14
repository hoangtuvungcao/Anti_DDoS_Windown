package notifier

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestNotifier_DiscordWebhook(t *testing.T) {
	var callCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&callCount, 1)
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["username"] != "WAF-Shield Defense Bot" {
			t.Errorf("Unexpected username: %v", body["username"])
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := NotifierConfig{
		Enabled:           true,
		DiscordWebhookURL: server.URL,
		CooldownSec:       1,
	}

	n := NewNotifier(cfg)
	defer n.Stop()

	n.Send(AlertPayload{
		Type:        AlertAttackStart,
		Title:       "DDoS Attack Detected",
		Description: "Target port 7777 is under flood",
		Vector:      "DISTRIBUTED /24 BOTNET",
		PeakPPS:     25000,
		PeakBPS:     20971520,
	})

	time.Sleep(100 * time.Millisecond)

	if atomic.LoadInt32(&callCount) != 1 {
		t.Errorf("Expected 1 webhook call, got %d", atomic.LoadInt32(&callCount))
	}
}

func TestNotifier_CooldownThrottling(t *testing.T) {
	var callCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&callCount, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := NotifierConfig{
		Enabled:           true,
		DiscordWebhookURL: server.URL,
		CooldownSec:       2,
	}

	n := NewNotifier(cfg)
	defer n.Stop()

	// Send 3 identical alerts immediately
	for i := 0; i < 3; i++ {
		n.Send(AlertPayload{
			Type:        AlertAttackStart,
			Title:       "DDoS Alert",
			Description: "Flood",
		})
	}

	time.Sleep(100 * time.Millisecond)

	// Due to cooldown, only 1 should be sent
	if atomic.LoadInt32(&callCount) != 1 {
		t.Errorf("Expected exactly 1 call due to cooldown, got %d", atomic.LoadInt32(&callCount))
	}
}
