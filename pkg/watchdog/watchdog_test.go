package watchdog

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnsureDriverFiles(t *testing.T) {
	// Create mock resources/bin directory with test file
	_ = os.MkdirAll(filepath.Join("resources", "bin"), 0755)
	testSys := filepath.Join("resources", "bin", "WinDivert64.sys")
	if _, err := os.Stat(testSys); os.IsNotExist(err) {
		_ = os.WriteFile(testSys, []byte("MOCK_DRIVER"), 0644)
	}

	err := EnsureDriverFiles()
	if err != nil {
		t.Fatalf("EnsureDriverFiles returned unexpected error: %v", err)
	}
}

func TestWatchdog_StartStop(t *testing.T) {
	wd := NewWatchdog(nil)
	wd.Start()
	time.Sleep(50 * time.Millisecond)
	wd.Stop()
}
