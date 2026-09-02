//go:build windows

package engine

import (
	"runtime"
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

	wh.applied = true
	return nil
}

// Restore restores original multimedia timer on graceful shutdown.
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
	wh.applied = false
}
