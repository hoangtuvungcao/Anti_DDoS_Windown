//go:build windows

package engine

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"syscall"
)

// WindowsHardening manages Windows TCP/IP kernel network stack hardening settings.
// Automatically applies optimal kernel DDoS protection on start and restores on exit.
type WindowsHardening struct {
	mu           sync.Mutex
	applied      bool
	origSettings map[string]string
}

var (
	hardeningOnce sync.Once
	hardeningInst *WindowsHardening

	winmmDLL            = syscall.NewLazyDLL("winmm.dll")
	procTimeBeginPeriod = winmmDLL.NewProc("timeBeginPeriod")
	procTimeEndPeriod   = winmmDLL.NewProc("timeEndPeriod")
)

// GetWindowsHardening returns the singleton hardening manager.
func GetWindowsHardening() *WindowsHardening {
	hardeningOnce.Do(func() {
		hardeningInst = &WindowsHardening{
			origSettings: make(map[string]string),
		}
	})
	return hardeningInst
}

// Apply applies safe Windows TCP/IP kernel hardening parameters and 1ms timer.
func (wh *WindowsHardening) Apply() error {
	if runtime.GOOS != "windows" {
		return nil // Non-Windows OS (Linux / Dev environment), skip safely
	}

	wh.mu.Lock()
	defer wh.mu.Unlock()

	if wh.applied {
		return nil
	}

	// 1. Enable 1ms high-precision multimedia timer for ultra-low gaming latency
	_, _, _ = procTimeBeginPeriod.Call(1)

	// 2. Recommended Windows TCP/IP hardening parameters
	targetKeys := map[string]string{
		"SynAttackProtect":             "2", // Protect against SYN floods
		"EnableICMPRedirect":           "0", // Disable ICMP redirect spoofing
		"EnableDeadGWDetect":           "0", // Disable Dead Gateway Detection hijack
		"DisableIPSourceRouting":       "2", // Highest IP source routing protection
		"TcpMaxConnectRetransmissions": "2", // Fast drop of dead connection attempts
	}

	const regPath = `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`

	for key, val := range targetKeys {
		// Query original value
		out, err := exec.Command("reg", "query", regPath, "/v", key).CombinedOutput()
		if err == nil {
			lines := strings.Split(string(out), "\n")
			for _, line := range lines {
				if strings.Contains(line, key) {
					fields := strings.Fields(line)
					if len(fields) >= 3 {
						wh.origSettings[key] = fields[len(fields)-1]
					}
				}
			}
		}

		// Set hardened value
		_ = exec.Command("reg", "add", regPath, "/v", key, "/t", "REG_DWORD", "/d", val, "/f").Run()
	}

	wh.applied = true
	return nil
}

// Restore restores original Windows TCP/IP parameters on graceful shutdown.
func (wh *WindowsHardening) Restore() {
	if runtime.GOOS != "windows" {
		return
	}

	wh.mu.Lock()
	defer wh.mu.Unlock()

	if !wh.applied {
		return
	}

	// Restore normal timer period
	_, _, _ = procTimeEndPeriod.Call(1)

	const regPath = `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`

	for key, origVal := range wh.origSettings {
		if origVal != "" {
			_ = exec.Command("reg", "add", regPath, "/v", key, "/t", "REG_DWORD", "/d", origVal, "/f").Run()
		}
	}

	wh.applied = false
	fmt.Println("\033[32m[Windows Hardening] Restored original TCP/IP kernel settings.\033[0m")
}
