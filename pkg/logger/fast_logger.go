package logger

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// LogLevel represents message severity
type LogLevel int

const (
	LevelInfo LogLevel = iota
	LevelWarn
	LevelAttack
	LevelBan
	LevelError
)

func (l LogLevel) String() string {
	switch l {
	case LevelInfo:
		return "INFO"
	case LevelWarn:
		return "WARN"
	case LevelAttack:
		return "ATTACK"
	case LevelBan:
		return "BAN"
	case LevelError:
		return "ERROR"
	default:
		return "LOG"
	}
}

// LogEvent represents an in-memory security event for UI display
type LogEvent struct {
	Timestamp time.Time
	Level     LogLevel
	Category  string
	Message   string
}

// FastLogger is a lock-free, asynchronous ring-buffer logger designed for extreme DDoS traffic.
// It never blocks packet processing threads and automatically rotates log files to prevent disk exhaustion.
type FastLogger struct {
	file         *os.File
	filePath     string
	logQueue     chan string
	eventHistory []LogEvent
	historyCap   int
	historyMu    sync.RWMutex
	stopCh       chan struct{}
	wg           sync.WaitGroup
	droppedLogs  atomic.Uint64
	maxSizeBytes int64
	maxBackups   int
	currentSize  int64
}

// NewFastLogger creates a high-performance asynchronous logger.
func NewFastLogger(filePath string, queueSize int, maxSizeBytes int64, maxBackups int) (*FastLogger, error) {
	if filePath == "" {
		filePath = filepath.Join("resources", "logs", "shield.log")
	}
	if queueSize <= 0 {
		queueSize = 10000 // 10k log messages buffer in RAM
	}
	if maxSizeBytes <= 0 {
		maxSizeBytes = 10 * 1024 * 1024 // 10MB per file
	}
	if maxBackups <= 0 {
		maxBackups = 5
	}

	// Ensure directory exists
	dir := filepath.Dir(filePath)
	if dir != "." && dir != "" {
		_ = os.MkdirAll(dir, 0755)
	}

	f, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file %s: %w", filePath, err)
	}

	fi, err := f.Stat()
	var initialSize int64
	if err == nil {
		initialSize = fi.Size()
	}

	fl := &FastLogger{
		file:         f,
		filePath:     filePath,
		logQueue:     make(chan string, queueSize),
		eventHistory: make([]LogEvent, 0, 100),
		historyCap:   100, // Keep last 100 events in memory for UI
		stopCh:       make(chan struct{}),
		maxSizeBytes: maxSizeBytes,
		maxBackups:   maxBackups,
		currentSize:  initialSize,
	}

	fl.wg.Add(1)
	go fl.writerLoop()

	return fl, nil
}

// writerLoop writes logs in batches to disk and handles file rotation.
func (fl *FastLogger) writerLoop() {
	defer fl.wg.Done()

	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()

	var batch []string
	batchCap := 500

	flush := func() {
		if len(batch) == 0 {
			return
		}
		var totalBytes int64
		for _, line := range batch {
			n, err := fl.file.WriteString(line + "\r\n")
			if err == nil {
				totalBytes += int64(n)
			}
		}
		fl.currentSize += totalBytes

		batch = batch[:0]

		// Check log rotation
		if fl.currentSize >= fl.maxSizeBytes {
			fl.rotate()
		}
	}

	for {
		select {
		case msg, ok := <-fl.logQueue:
			if !ok {
				flush()
				return
			}
			batch = append(batch, msg)
			if len(batch) >= batchCap {
				flush()
			}

		case <-ticker.C:
			flush()

		case <-fl.stopCh:
			// Drain remaining logs
			for {
				select {
				case msg := <-fl.logQueue:
					batch = append(batch, msg)
				default:
					flush()
					return
				}
			}
		}
	}
}

// rotate moves current log to backup and creates a fresh log file.
func (fl *FastLogger) rotate() {
	if fl.file != nil {
		_ = fl.file.Close()
	}

	// Shift existing backups: shield.log.4 -> shield.log.5, etc.
	for i := fl.maxBackups - 1; i >= 1; i-- {
		oldPath := fmt.Sprintf("%s.%d", fl.filePath, i)
		newPath := fmt.Sprintf("%s.%d", fl.filePath, i+1)
		_ = os.Rename(oldPath, newPath)
	}

	// Rename current log to .1
	_ = os.Rename(fl.filePath, fmt.Sprintf("%s.1", fl.filePath))

	// Create new log file
	f, err := os.OpenFile(fl.filePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err == nil {
		fl.file = f
		fl.currentSize = 0
	}
}

// Log writes a message asynchronously. If the queue is full during a massive attack,
// it drops the log rather than blocking worker packet processing (Backpressure defense).
func (fl *FastLogger) Log(level LogLevel, category, format string, v ...interface{}) {
	msg := fmt.Sprintf(format, v...)
	now := time.Now()
	formattedLine := fmt.Sprintf("[%s] [%s] [%s] %s", now.Format("2006-01-02 15:04:05"), level.String(), category, msg)

	// Save to in-memory event history for Live UI
	fl.historyMu.Lock()
	if len(fl.eventHistory) >= fl.historyCap {
		fl.eventHistory = fl.eventHistory[1:]
	}
	fl.eventHistory = append(fl.eventHistory, LogEvent{
		Timestamp: now,
		Level:     level,
		Category:  category,
		Message:   msg,
	})
	fl.historyMu.Unlock()

	// Push to async disk queue
	select {
	case fl.logQueue <- formattedLine:
	default:
		fl.droppedLogs.Add(1) // Queue full under extreme flood, drop safely to protect disk I/O
	}
}

// Info logs an informational message.
func (fl *FastLogger) Info(category, format string, v ...interface{}) {
	fl.Log(LevelInfo, category, format, v...)
}

// Warn logs a warning message.
func (fl *FastLogger) Warn(category, format string, v ...interface{}) {
	fl.Log(LevelWarn, category, format, v...)
}

// Attack logs a detected DDoS attack vector.
func (fl *FastLogger) Attack(category, format string, v ...interface{}) {
	fl.Log(LevelAttack, category, format, v...)
}

// Ban logs an IP or Subnet ban event.
func (fl *FastLogger) Ban(category, format string, v ...interface{}) {
	fl.Log(LevelBan, category, format, v...)
}

// Error logs an error event.
func (fl *FastLogger) Error(category, format string, v ...interface{}) {
	fl.Log(LevelError, category, format, v...)
}

// Println implements compatibility for stdlib logger.
func (fl *FastLogger) Println(v ...interface{}) {
	fl.Info("SYSTEM", "%s", fmt.Sprint(v...))
}

// Printf implements compatibility for stdlib logger.
func (fl *FastLogger) Printf(format string, v ...interface{}) {
	fl.Info("SYSTEM", format, v...)
}

// GetRecentEvents returns a snapshot of recent in-memory security events for the UI.
func (fl *FastLogger) GetRecentEvents(maxCount int) []LogEvent {
	fl.historyMu.RLock()
	defer fl.historyMu.RUnlock()

	n := len(fl.eventHistory)
	if maxCount > n {
		maxCount = n
	}

	res := make([]LogEvent, maxCount)
	copy(res, fl.eventHistory[n-maxCount:])
	return res
}

// GetDroppedLogsCount returns count of logs dropped due to disk backpressure.
func (fl *FastLogger) GetDroppedLogsCount() uint64 {
	return fl.droppedLogs.Load()
}

// Close flushes all queued logs and safely closes the file.
func (fl *FastLogger) Close() {
	close(fl.stopCh)
	fl.wg.Wait()
	if fl.file != nil {
		_ = fl.file.Sync()
		_ = fl.file.Close()
	}
}
