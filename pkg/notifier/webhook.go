package notifier

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// NotifierConfig holds settings for Discord and Telegram alerts.
type NotifierConfig struct {
	Enabled           bool   `json:"enabled"`
	DiscordWebhookURL string `json:"discord_webhook_url"`
	TelegramBotToken  string `json:"telegram_bot_token"`
	TelegramChatID    string `json:"telegram_chat_id"`
	CooldownSec       int    `json:"cooldown_sec"`
}

// AlertEvent represents an incident to notify about.
type AlertType int

const (
	AlertAttackStart AlertType = iota
	AlertAttackMitigated
	AlertSubnetBanned
)

type AlertPayload struct {
	Type          AlertType
	Title         string
	Description   string
	Vector        string
	PeakPPS       uint64
	PeakBPS       uint64
	TotalDrops    uint64
	QuarantineCIDR string
	Timestamp     time.Time
}

// Notifier handles asynchronous webhook dispatch.
type Notifier struct {
	cfg       NotifierConfig
	mu        sync.Mutex
	lastAlert map[AlertType]time.Time
	client    *http.Client
	queue     chan AlertPayload
	stopCh    chan struct{}
}

// NewNotifier creates an alert notifier worker.
func NewNotifier(cfg NotifierConfig) *Notifier {
	if cfg.CooldownSec <= 0 {
		cfg.CooldownSec = 30
	}

	n := &Notifier{
		cfg:       cfg,
		lastAlert: make(map[AlertType]time.Time),
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
		queue:  make(chan AlertPayload, 100),
		stopCh: make(chan struct{}),
	}

	if cfg.Enabled {
		go n.worker()
	}

	return n
}

// Send queues an alert for asynchronous sending.
func (n *Notifier) Send(payload AlertPayload) {
	if !n.cfg.Enabled {
		return
	}

	payload.Timestamp = time.Now()

	n.mu.Lock()
	last, ok := n.lastAlert[payload.Type]
	cooldown := time.Duration(n.cfg.CooldownSec) * time.Second
	if ok && time.Since(last) < cooldown {
		n.mu.Unlock()
		return // Throttled to prevent spam
	}
	n.lastAlert[payload.Type] = time.Now()
	n.mu.Unlock()

	select {
	case n.queue <- payload:
	default:
		// Queue full, drop to prevent blocking
	}
}

// Stop gracefully shuts down the notifier worker.
func (n *Notifier) Stop() {
	if !n.cfg.Enabled {
		return
	}
	close(n.stopCh)
}

func (n *Notifier) worker() {
	for {
		select {
		case <-n.stopCh:
			return
		case alert := <-n.queue:
			if n.cfg.DiscordWebhookURL != "" {
				_ = n.sendDiscord(alert)
			}
			if n.cfg.TelegramBotToken != "" && n.cfg.TelegramChatID != "" {
				_ = n.sendTelegram(alert)
			}
		}
	}
}

func (n *Notifier) sendDiscord(alert AlertPayload) error {
	var color int
	switch alert.Type {
	case AlertAttackStart:
		color = 15158332 // Red (#E74C3C)
	case AlertAttackMitigated:
		color = 3066993 // Green (#2ECC71)
	case AlertSubnetBanned:
		color = 15105570 // Orange (#E67E22)
	default:
		color = 3447003 // Blue (#3498DB)
	}

	mbps := float64(alert.PeakBPS) / (1024 * 1024)

	fields := []map[string]interface{}{
		{"name": "Attack Vector", "value": alert.Vector, "inline": true},
		{"name": "Peak Traffic", "value": fmt.Sprintf("%d PPS (%.2f MB/s)", alert.PeakPPS, mbps), "inline": true},
		{"name": "Status", "value": "[ACTIVE] Host mitigation policy applied", "inline": false},
	}

	if alert.QuarantineCIDR != "" {
		fields = append(fields, map[string]interface{}{
			"name": "Quarantined Subnet", "value": alert.QuarantineCIDR, "inline": true,
		})
	}

	embed := map[string]interface{}{
		"title":       alert.Title,
		"description": alert.Description,
		"color":       color,
		"fields":      fields,
		"footer": map[string]string{
			"text": "WAF-Shield Enterprise Cyber Defense for Windows",
		},
		"timestamp": alert.Timestamp.Format(time.RFC3339),
	}

	body := map[string]interface{}{
		"username":   "WAF-Shield Defense Bot",
		"avatar_url": "https://img.icons8.com/color/96/000000/shield.png",
		"embeds":     []interface{}{embed},
	}

	data, err := json.Marshal(body)
	if err != nil {
		return err
	}

	resp, err := n.client.Post(n.cfg.DiscordWebhookURL, "application/json", bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

func (n *Notifier) sendTelegram(alert AlertPayload) error {
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", n.cfg.TelegramBotToken)
	mbps := float64(alert.PeakBPS) / (1024 * 1024)

	var prefix string
	switch alert.Type {
	case AlertAttackStart:
		prefix = "[ALERT]"
	case AlertAttackMitigated:
		prefix = "[RESOLVED]"
	case AlertSubnetBanned:
		prefix = "[BANNED]"
	default:
		prefix = "[INFO]"
	}

	text := fmt.Sprintf(
		"<b>%s %s</b>\n\n%s\n- <b>Vector:</b> <code>%s</code>\n- <b>Peak Traffic:</b> <code>%d PPS (%.2f MB/s)</code>\n- <b>Protection:</b> <code>Active & Filtered</code>\n\n<i>WAF-Shield Enterprise (Windows)</i>",
		prefix, alert.Title, alert.Description, alert.Vector, alert.PeakPPS, mbps,
	)


	body := map[string]interface{}{
		"chat_id":    n.cfg.TelegramChatID,
		"text":       text,
		"parse_mode": "HTML",
	}

	data, err := json.Marshal(body)
	if err != nil {
		return err
	}

	resp, err := n.client.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}
