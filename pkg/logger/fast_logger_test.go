package logger

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFastLogger_BasicAndRotation(t *testing.T) {
	tempDir := t.TempDir()
	logPath := filepath.Join(tempDir, "test_shield.log")

	// Max size 500 bytes to force fast rotation
	fl, err := NewFastLogger(logPath, 1000, 500, 3)
	if err != nil {
		t.Fatalf("Failed to create FastLogger: %v", err)
	}
	defer fl.Close()

	// Write 50 log messages
	for i := 0; i < 50; i++ {
		fl.Attack("TEST_DDOS", "Flooding attempt from 1.2.3.4, count=%d", i)
	}

	// Give async worker time to flush
	time.Sleep(400 * time.Millisecond)

	// Verify events in memory
	events := fl.GetRecentEvents(10)
	if len(events) == 0 {
		t.Errorf("Expected in-memory events, got 0")
	}

	// Check file exists
	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		t.Errorf("Log file was not created on disk: %s", logPath)
	}
}

func TestFastLogger_Backpressure(t *testing.T) {
	tempDir := t.TempDir()
	logPath := filepath.Join(tempDir, "bp_shield.log")

	// Tiny queue size to test non-blocking drop under backpressure
	fl, err := NewFastLogger(logPath, 5, 1024*1024, 2)
	if err != nil {
		t.Fatalf("Failed to create FastLogger: %v", err)
	}
	defer fl.Close()

	// Rapidly spam 1,000 logs without blocking
	for i := 0; i < 1000; i++ {
		fl.Info("SPAM", "Message %d", i)
	}

	// Should not deadlock or crash
	time.Sleep(300 * time.Millisecond)
}
