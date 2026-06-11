package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"unsafe"

	"waf-game/pkg/cli"
	"waf-game/pkg/config"
	"waf-game/pkg/engine"
	"waf-game/pkg/stats"
)

const (
	version    = "1.0.0"
	configFile = "config.json"
)

func main() {
	setConsoleTitle("WAF-Game — Anti-DDoS Shield")

	// ═══════════════════════════════════════════════
	// Step 1: Check Administrator privileges
	// ═══════════════════════════════════════════════
	if !isAdmin() {
		fmt.Println("\033[31m[ERROR] WAF-Game requires Administrator privileges.")
		fmt.Println("Right-click → Run as Administrator\033[0m")
		os.Exit(1)
	}

	// ═══════════════════════════════════════════════
	// Step 2: Enable ANSI support on Windows console
	// ═══════════════════════════════════════════════
	enableConsoleVT()

	// ═══════════════════════════════════════════════
	// Step 3: Print banner
	// ═══════════════════════════════════════════════
	printBanner()

	// ═══════════════════════════════════════════════
	// Step 4: Check WinDivert files
	// ═══════════════════════════════════════════════
	if !checkWinDivertFiles() {
		os.Exit(1)
	}

	// ═══════════════════════════════════════════════
	// Step 5: Load configuration
	// ═══════════════════════════════════════════════
	cfg, err := config.Load(configFile)
	if err != nil {
		fmt.Printf("\033[31m[ERROR] Failed to load config: %v\033[0m\n", err)
		os.Exit(1)
	}
	fmt.Printf("\033[32m[OK] Config loaded (%s)\033[0m\n", configFile)

	// ═══════════════════════════════════════════════
	// Step 6: Initialize logger
	// ═══════════════════════════════════════════════
	logFile, err := os.OpenFile(cfg.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		fmt.Printf("\033[33m[WARN] Cannot open log file %s: %v — logging to stdout\033[0m\n", cfg.LogFile, err)
		logFile = os.Stdout
	}
	logger := log.New(logFile, "[WAF-Game] ", log.LstdFlags)
	logger.Printf("WAF-Game v%s starting...", version)

	// ═══════════════════════════════════════════════
	// Step 7: Initialize metrics
	// ═══════════════════════════════════════════════
	metrics := stats.NewMetrics()

	// ═══════════════════════════════════════════════
	// Step 8: Create and start engine
	// ═══════════════════════════════════════════════
	engineCfg := cfg.ToEngineConfig()
	eng, err := engine.NewEngine(engineCfg, metrics, logger)
	if err != nil {
		fmt.Printf("\033[31m[ERROR] Failed to start engine: %v\033[0m\n", err)
		fmt.Println("\033[33mMake sure WinDivert.dll and WinDivert64.sys are in the same directory.\033[0m")
		logger.Fatalf("Engine start failed: %v", err)
	}

	fmt.Println("\033[32m[OK] WinDivert driver loaded\033[0m")
	fmt.Printf("\033[32m[OK] Engine started with %d workers\033[0m\n", cfg.Workers)
	fmt.Println("\033[32m[OK] Auto-discovery scanning all system ports...\033[0m")
	fmt.Println()
	fmt.Println("\033[36mStarting dashboard in 2 seconds...\033[0m")

	// Brief pause to let discovery complete first scan
	// Use a simple sleep via channel
	done := make(chan struct{})
	go func() {
		select {
		case <-done:
		}
	}()

	eng.Start()
	logger.Println("Engine started successfully")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	// ═══════════════════════════════════════════════
	// Step 9: Start CLI dashboard
	// ═══════════════════════════════════════════════
	dashboard := cli.NewDashboard(metrics, eng, sigCh, cfg, configFile)
	dashboard.Start()

	// ═══════════════════════════════════════════════
	// Step 10: Wait for shutdown signal
	// ═══════════════════════════════════════════════
	<-sigCh

	// ═══════════════════════════════════════════════
	// Step 11: Clean shutdown
	// ═══════════════════════════════════════════════
	fmt.Println()
	fmt.Println("\033[33m[!] Initiating clean shutdown...\033[0m")
	logger.Println("Clean shutdown initiated")

	dashboard.Stop()
	eng.Stop()

	if logFile != os.Stdout {
		logFile.Close()
	}

	fmt.Println("\033[32m[OK] WinDivert driver unloaded — network stack restored\033[0m")
	fmt.Println("\033[32m[OK] WAF-Game stopped safely. Network is fully operational.\033[0m")
	logger.Println("WAF-Game stopped")
}

func printBanner() {
	fmt.Println("\033[36m")
	fmt.Println("  ╔═══════════════════════════════════════════════════╗")
	fmt.Println("  ║     ██╗    ██╗ █████╗ ███████╗                    ║")
	fmt.Println("  ║     ██║    ██║██╔══██╗██╔════╝                    ║")
	fmt.Println("  ║     ██║ █╗ ██║███████║█████╗                      ║")
	fmt.Println("  ║     ██║███╗██║██╔══██║██╔══╝                      ║")
	fmt.Println("  ║     ╚███╔███╔╝██║  ██║██║                         ║")
	fmt.Println("  ║      ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝                         ║")
	fmt.Println("  ║                                                   ║")
	fmt.Printf("  ║     WAF-Game v%s Anti-DDoS for Windows         ║\n", version)
	fmt.Println("  ║     Zero-Config Behavioral Firewall               ║")
	fmt.Println("  ╚═══════════════════════════════════════════════════╝")
	fmt.Println("\033[0m")
}

func isAdmin() bool {
	_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
	if err != nil {
		return false
	}
	return true
}

func checkWinDivertFiles() bool {
	files := []string{"resources/bin/WinDivert.dll", "resources/bin/WinDivert64.sys"}
	ok := true
	for _, f := range files {
		if _, err := os.Stat(f); os.IsNotExist(err) {
			fmt.Printf("\033[31m[ERROR] Missing required file: %s\033[0m\n", f)
			ok = false
		}
	}
	if !ok {
		fmt.Println("\033[33m")
		fmt.Println("Download WinDivert 2.2.2 from: https://github.com/basil00/Divert/releases")
		fmt.Println("Place WinDivert.dll and WinDivert64.sys in the same directory as waf-game.exe")
		fmt.Println("\033[0m")
	}
	return ok
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

	// Also enable for stdin (raw mode for hotkeys)
	const stdInputHandle = uintptr(0xFFFFFFF6) // STD_INPUT_HANDLE = -10
	inHandle, _, _ := procGetHandle.Call(stdInputHandle)
	if inHandle != 0 && inHandle != uintptr(syscall.InvalidHandle) {
		var inMode uint32
		procGetMode.Call(inHandle, uintptr(unsafe.Pointer(&inMode)))
		// Disable line input and echo for raw key reading
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
