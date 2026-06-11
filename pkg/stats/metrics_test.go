package stats

import (
	"testing"
)

func TestMetrics_Snapshot(t *testing.T) {
	m := NewMetrics()

	m.InboundPPS.Add(150)
	m.InboundBPS.Add(10240)
	m.Layer1Drops.Add(10)
	m.Layer2Drops.Add(5)
	m.Layer3Drops.Add(3)
	m.Layer4Drops.Add(2)

	// Before snapshot, snap values should be 0
	if m.SnapPPS != 0 || m.SnapBPS != 0 || m.SnapL1 != 0 {
		t.Errorf("Expected initial snapshot values to be 0")
	}

	// Capture snapshot
	m.Snapshot()

	if m.SnapPPS != 150 {
		t.Errorf("Expected SnapPPS 150, got %d", m.SnapPPS)
	}
	if m.SnapBPS != 10240 {
		t.Errorf("Expected SnapBPS 10240, got %d", m.SnapBPS)
	}
	if m.SnapL1 != 10 || m.SnapL2 != 5 || m.SnapL3 != 3 || m.SnapL4 != 2 {
		t.Errorf("Snap drops mismatch: L1=%d, L2=%d, L3=%d, L4=%d", m.SnapL1, m.SnapL2, m.SnapL3, m.SnapL4)
	}

	total := m.TotalDrops()
	if total != 20 {
		t.Errorf("Expected TotalDrops 20, got %d", total)
	}

	// After snapshot, live counters should be reset to 0
	if m.InboundPPS.Load() != 0 || m.InboundBPS.Load() != 0 || m.Layer1Drops.Load() != 0 {
		t.Errorf("Expected live counters to be reset to 0 after Snapshot()")
	}
}
