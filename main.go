//go:build windows

package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"

	"waf-game/pkg/cli"
	"waf-game/pkg/config"
	"waf-game/pkg/engine"
	"waf-game/pkg/logger"
	"waf-game/pkg/notifier"
	"waf-game/pkg/service"
	"waf-game/pkg/stats"
	"waf-game/pkg/watchdog"
	"waf-game/pkg/web"
)

const (
	version    = "3.5.3"
	configFile = "config.json"
)

func main() {
	// ═══════════════════════════════════════════════
	// Step 0: Ensure Working Directory is Executable's Directory (Critical for Windows Services!)
	// ═══════════════════════════════════════════════
	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		_ = os.Chdir(exeDir)
	}

	installFlag := flag.Bool("install", false, "Install as Windows Background Service")
	uninstallFlag := flag.Bool("uninstall", false, "Uninstall Windows Service")
	startFlag := flag.Bool("start", false, "Start Windows Service in background")
	stopFlag := flag.Bool("stop", false, "Stop Windows Service")
	serviceFlag := flag.Bool("service", false, "Internal flag: run as Windows Service daemon")
	flag.Parse()

	if *installFlag {
		if err := service.Install(); err != nil {
			fmt.Printf("[ERROR] %v\n", err)
		}
		return
	}
	if *uninstallFlag {
		if err := service.Uninstall(); err != nil {
			fmt.Printf("[ERROR] %v\n", err)
		}
		return
	}
	if *startFlag {
		if err := service.Start(); err != nil {
			fmt.Printf("[ERROR] %v\n", err)
		}
		return
	}
	if *stopFlag {
		if err := service.Stop(); err != nil {
			fmt.Printf("[ERROR] %v\n", err)
		}
		return
	}

	// ═══════════════════════════════════════════════
	// Step 1: Run as Native Windows Service if requested
	// ═══════════════════════════════════════════════
	if *serviceFlag {
		var eng *engine.Engine
		var fastLog *logger.FastLogger
		var webServer *web.Server
		var wd *watchdog.Watchdog
		var botNotifier *notifier.Notifier

		err := service.RunService(func() {
			_ = watchdog.EnsureDriverFiles()
			_ = engine.GetWindowsHardening().Apply()

			cfg, err := config.Load(configFile)
			if err != nil {
				return
			}

			fastLog, _ = logger.NewFastLogger(cfg.LogFile, 10000, 10*1024*1024, 5)
			if fastLog != nil {
				fastLog.Info("SYSTEM", "WAF-Shield Enterprise v%s started as Windows Service", version)
			}

			metrics := stats.NewMetrics()
			botNotifier = notifier.NewNotifier(notifier.NotifierConfig{
				Enabled:           cfg.Notifications.Enabled,
				DiscordWebhookURL: cfg.Notifications.DiscordWebhookURL,
				TelegramBotToken:  cfg.Notifications.TelegramBotToken,
				TelegramChatID:    cfg.Notifications.TelegramChatID,
				CooldownSec:       cfg.Notifications.CooldownSec,
			})

			eng, err = engine.NewEngine(cfg.ToEngineConfig(), metrics, fastLog)
			if err != nil {
				if fastLog != nil {
					fastLog.Error("FATAL", "Failed to start engine in service mode: %v", err)
				}
				return
			}
			wireNotifier(eng, botNotifier)
			eng.Start()

			webServer = web.NewServer(web.WebConfig{
				Enabled:  cfg.WebDashboard.Enabled,
				Port:     cfg.WebDashboard.Port,
				Username: cfg.WebDashboard.Username,
				Password: cfg.WebDashboard.Password,
				AllowLAN: cfg.WebDashboard.AllowLAN,
			}, eng, metrics, fastLog)
			if err := webServer.Start(); err != nil && fastLog != nil {
				fastLog.Error("WEB", "Dashboard disabled: %v", err)
			}

			wd = watchdog.NewWatchdog(fastLog)
			wd.Start()
		}, func() {
			if wd != nil {
				wd.Stop()
			}
			if webServer != nil {
				webServer.Stop()
			}
			if botNotifier != nil {
				botNotifier.Stop()
			}
			if eng != nil {
				eng.Stop()
			}
			if fastLog != nil {
				fastLog.Close()
			}
			engine.GetWindowsHardening().Restore()
		})
		if err == nil {
			return
		}
	}

	// ═══════════════════════════════════════════════
	// Step 2: Interactive CLI Mode
	// ═══════════════════════════════════════════════
	setConsoleTitle("WAF-Shield — Universal Anti-DDoS Shield (Windows)")

	if !isAdmin() {
		fmt.Println("[ERROR] WAF-Shield requires Administrator privileges.")
		os.Exit(1)
	}

	enableConsoleVT()
	_ = watchdog.EnsureDriverFiles()
	_ = engine.GetWindowsHardening().Apply()

	printBanner()

	if !checkWinDivertFiles() {
		os.Exit(1)
	}

	cfg, err := config.Load(configFile)
	if err != nil {
		fmt.Printf("[ERROR] Failed to load config: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[OK] Config loaded (%s)\n", configFile)

	fastLog, err := logger.NewFastLogger(cfg.LogFile, 10000, 10*1024*1024, 5)
	if err != nil {
		fmt.Printf("[WARN] Cannot open log file %s: %v — continuing with fallback\n", cfg.LogFile, err)
	}
	if fastLog != nil {
		fastLog.Info("SYSTEM", "WAF-Shield Enterprise v%s starting on Windows...", version)
	}

	metrics := stats.NewMetrics()
	botNotifier := notifier.NewNotifier(notifier.NotifierConfig{
		Enabled:           cfg.Notifications.Enabled,
		DiscordWebhookURL: cfg.Notifications.DiscordWebhookURL,
		TelegramBotToken:  cfg.Notifications.TelegramBotToken,
		TelegramChatID:    cfg.Notifications.TelegramChatID,
		CooldownSec:       cfg.Notifications.CooldownSec,
	})

	eng, err := engine.NewEngine(cfg.ToEngineConfig(), metrics, fastLog)
	if err != nil {
		fmt.Printf("[ERROR] Failed to start engine: %v\n", err)
		fmt.Println("Make sure WinDivert.dll and WinDivert64.sys are in the same directory.")
		if fastLog != nil {
			fastLog.Error("FATAL", "Engine start failed: %v", err)
			fastLog.Close()
		}
		os.Exit(1)
	}
	wireNotifier(eng, botNotifier)

	fmt.Println("[OK] WinDivert driver loaded")
	fmt.Printf("[OK] Engine started with %d workers\n", cfg.Workers)
	fmt.Println("[OK] Auto-discovery scanning all system ports (1-65535)...")

	eng.Start()
	if fastLog != nil {
		fastLog.Info("SYSTEM", "Engine started successfully with all shields active")
	}

	webServer := web.NewServer(web.WebConfig{
		Enabled:  cfg.WebDashboard.Enabled,
		Port:     cfg.WebDashboard.Port,
		Username: cfg.WebDashboard.Username,
		Password: cfg.WebDashboard.Password,
		AllowLAN: cfg.WebDashboard.AllowLAN,
	}, eng, metrics, fastLog)
	webStarted := webServer.Start() == nil
	if !webStarted {
		fmt.Printf("[WARN] Web Dashboard could not start on port %d — port may conflict with IslePilot/game server.\n", cfg.WebDashboard.Port)
		fmt.Println("[WARN] Change web_dashboard.port in config.json (e.g. 8181) and restart.")
	}
	if cfg.WebDashboard.Enabled && webStarted {
		activePort := webServer.GetActivePort()
		if activePort != cfg.WebDashboard.Port {
			fmt.Printf("[OK] Web Dashboard: http://127.0.0.1:%d  (port %d was busy, auto-fallback used)\n", activePort, cfg.WebDashboard.Port)
		} else {
			fmt.Printf("[OK] Web Dashboard: http://127.0.0.1:%d\n", activePort)
		}
		if cfg.WebDashboard.AllowLAN {
			fmt.Printf("[OK] LAN Access:    http://YOUR_SERVER_IP:%d\n", webServer.GetActivePort())
		}
	}

	wd := watchdog.NewWatchdog(fastLog)
	wd.Start()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	fmt.Println()
	fmt.Println("Starting Cyber Security Dashboard in 1 second...")
	time.Sleep(1 * time.Second)

	dashboard := cli.NewDashboard(metrics, eng, sigCh, cfg, configFile)
	dashboard.Start()
	<-sigCh
	dashboard.Stop()

	fmt.Println()
	fmt.Println("[!] Initiating clean shutdown...")
	if fastLog != nil {
		fastLog.Info("SYSTEM", "Clean shutdown initiated by user")
	}

	wd.Stop()
	webServer.Stop()
	botNotifier.Stop()
	eng.Stop()

	if fastLog != nil {
		fastLog.Close()
	}

	fmt.Println("[OK] WinDivert driver unloaded — network stack restored")
	engine.GetWindowsHardening().Restore()
	fmt.Println("[OK] WAF-Shield stopped safely. Network is fully operational.")
}

func wireNotifier(eng *engine.Engine, n *notifier.Notifier) {
	if eng == nil || n == nil {
		return
	}
	eng.SetAttackCallback(func(active bool, vector string, pps, bps, drops uint64) {
		alertType := notifier.AlertAttackMitigated
		title := "DDoS incident mitigated"
		description := "Traffic returned below the configured thresholds."
		if active {
			alertType = notifier.AlertAttackStart
			title = "DDoS attack detected"
			description = "WAF-Shield escalated to War Mode and applied strict mitigation limits."
		}
		n.Send(notifier.AlertPayload{Type: alertType, Title: title, Description: description, Vector: vector, PeakPPS: pps, PeakBPS: bps, TotalDrops: drops})
	})
}

func printBanner() {
	fmt.Println()
	fmt.Println("  +---------------------------------------------------+")
	fmt.Printf("  |     WAF-Shield v%s Enterprise for Windows      |\n", version)
	fmt.Println("  |     Universal All-Port Cyber Defense Engine       |")
	fmt.Println("  +---------------------------------------------------+")
	fmt.Println()
}

func isAdmin() bool {
	f, err := os.Open("\\\\.\\PHYSICALDRIVE0")
	if err != nil {
		return false
	}
	f.Close() // Bug fix: prevent resource leak
	return true
}

func checkWinDivertFiles() bool {
	// Check root directory first, then fallback to resources/bin/
	hasRoot := true
	for _, f := range []string{"WinDivert.dll", "WinDivert64.sys"} {
		if _, err := os.Stat(f); os.IsNotExist(err) {
			hasRoot = false
			break
		}
	}
	if hasRoot {
		return true
	}

	hasBin := true
	for _, f := range []string{"resources/bin/WinDivert.dll", "resources/bin/WinDivert64.sys"} {
		if _, err := os.Stat(f); os.IsNotExist(err) {
			hasBin = false
			break
		}
	}
	if hasBin {
		return true
	}

	fmt.Println("[ERROR] Missing WinDivert driver files (WinDivert.dll and WinDivert64.sys).")
	fmt.Println("Download WinDivert 2.2.2 from: https://github.com/basil00/Divert/releases")
	fmt.Println("Place WinDivert.dll and WinDivert64.sys in the same directory as waf-game.exe")
	return false
}

func enableConsoleVT() {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	procSetMode := kernel32.NewProc("SetConsoleMode")
	procGetMode := kernel32.NewProc("GetConsoleMode")
	procGetHandle := kernel32.NewProc("GetStdHandle")

	const stdOutputHandle = uintptr(0xFFFFFFF5) // STD_OUTPUT_HANDLE = -11
	const enableVTProcessing = 0x0004
	const enableProcessedOutput = 0x0001

	handle, _, _ := procGetHandle.Call(stdOutputHandle)
	if handle == 0 || handle == uintptr(syscall.InvalidHandle) {
		return
	}

	var mode uint32
	r, _, _ := procGetMode.Call(handle, uintptr(unsafe.Pointer(&mode)))
	if r == 0 {
		return
	}

	procSetMode.Call(handle, uintptr(mode|enableVTProcessing|enableProcessedOutput))

	const stdInputHandle = uintptr(0xFFFFFFF6) // STD_INPUT_HANDLE = -10
	inHandle, _, _ := procGetHandle.Call(stdInputHandle)
	if inHandle != 0 && inHandle != uintptr(syscall.InvalidHandle) {
		var inMode uint32
		procGetMode.Call(inHandle, uintptr(unsafe.Pointer(&inMode)))
		const enableLineInput = 0x0002
		const enableEchoInput = 0x0004
		newMode := inMode &^ enableLineInput &^ enableEchoInput
		procSetMode.Call(inHandle, uintptr(newMode))
	}
}

func setConsoleTitle(title string) {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	procSetConsoleTitle := kernel32.NewProc("SetConsoleTitleW")
	titlePtr, err := syscall.UTF16PtrFromString(title)
	if err == nil {
		procSetConsoleTitle.Call(uintptr(unsafe.Pointer(titlePtr)))
	}
}
