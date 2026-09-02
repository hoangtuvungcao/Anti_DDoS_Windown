package watchdog

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"waf-game/pkg/logger"
)

// EnsureDriverFiles verifies that WinDivert.dll and WinDivert64.sys are present.
// If missing from root but present in resources/bin/, automatically copies them to root.
func EnsureDriverFiles() error {
	required := []string{"WinDivert.dll", "WinDivert64.sys"}

	for _, file := range required {
		if _, err := os.Stat(file); os.IsNotExist(err) {
			// Check resources/bin/
			srcPath := filepath.Join("resources", "bin", file)
			if _, srcErr := os.Stat(srcPath); srcErr == nil {
				// Copy from resources/bin/ to current dir
				if copyErr := copyFile(srcPath, file); copyErr != nil {
					return fmt.Errorf("failed to copy %s to current directory: %w", file, copyErr)
				}
				fmt.Printf("\033[32m[Auto-Driver] Restored %s to application directory.\033[0m\n", file)
			}
		}
	}
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}

// Watchdog monitors worker health and memory pressure.
type Watchdog struct {
	fastLog *logger.FastLogger
	stopCh  chan struct{}
}

// NewWatchdog creates a background health watchdog.
func NewWatchdog(fastLog *logger.FastLogger) *Watchdog {
	return &Watchdog{
		fastLog: fastLog,
		stopCh:  make(chan struct{}),
	}
}

// Start runs the periodic health monitor.
func (w *Watchdog) Start() {
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-w.stopCh:
				return
			case <-ticker.C:
				var m runtime.MemStats
				runtime.ReadMemStats(&m)
				allocMB := float64(m.Alloc) / (1024 * 1024)
				sysMB := float64(m.Sys) / (1024 * 1024)

				// Log warning if memory abnormally spikes above 500MB
				if allocMB > 500 && w.fastLog != nil {
					w.fastLog.Warn("WATCHDOG", "Memory pressure high: Alloc=%.1f MB, Sys=%.1f MB", allocMB, sysMB)
				}
			}
		}
	}()
}

// Stop stops the watchdog.
func (w *Watchdog) Stop() {
	close(w.stopCh)
}
