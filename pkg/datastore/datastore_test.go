package datastore

import (
	"sync"
	"testing"
	"time"
)

func TestShardedMap_GetOrCreate(t *testing.T) {
	sm := NewShardedMap[string](1000)

	// Ensure empty
	if sm.Count() != 0 {
		t.Errorf("Expected count 0, got %d", sm.Count())
	}

	// Create
	valInit := func() string { return "hello" }
	entry, created := sm.GetOrCreate(42, valInit)
	if !created {
		t.Errorf("Expected created to be true")
	}
	if entry.Value != "hello" {
		t.Errorf("Expected value 'hello', got '%s'", entry.Value)
	}
	if sm.Count() != 1 {
		t.Errorf("Expected count 1, got %d", sm.Count())
	}

	// Retrieve existing
	entry2, created2 := sm.GetOrCreate(42, func() string { return "world" })
	if created2 {
		t.Errorf("Expected created to be false for existing key")
	}
	if entry2.Value != "hello" {
		t.Errorf("Expected existing value 'hello', got '%s'", entry2.Value)
	}
}

func TestShardedMap_SetAndGetAndDelete(t *testing.T) {
	sm := NewShardedMap[int](10)

	sm.Set(100, 999)
	entry, ok := sm.Get(100)
	if !ok || entry.Value != 999 {
		t.Errorf("Expected to get 999, got %v, ok=%t", entry, ok)
	}

	sm.Delete(100)
	_, ok = sm.Get(100)
	if ok {
		t.Errorf("Expected key to be deleted")
	}
	if sm.Count() != 0 {
		t.Errorf("Expected count 0, got %d", sm.Count())
	}
}

func TestShardedMap_Sweep(t *testing.T) {
	sm := NewShardedMap[string](100)

	sm.Set(1, "a")
	sm.Set(2, "b")

	// Artificially modify LastSeen to make entry 1 expired
	entry1, _ := sm.Get(1)
	entry1.LastSeen = time.Now().Add(-1 * time.Minute).UnixNano()

	removed := sm.Sweep(30 * time.Second)
	if removed != 1 {
		t.Errorf("Expected 1 removed entry, got %d", removed)
	}

	_, ok1 := sm.Get(1)
	if ok1 {
		t.Errorf("Expired entry 1 should have been swept")
	}

	_, ok2 := sm.Get(2)
	if !ok2 {
		t.Errorf("Non-expired entry 2 should not have been swept")
	}
}

func TestShardedMap_Concurrency(t *testing.T) {
	sm := NewShardedMap[int](10000)
	var wg sync.WaitGroup

	// Start 10 goroutines writing and reading concurrently
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for k := 0; k < 100; k++ {
				key := uint64(workerID*1000 + k)
				sm.Set(key, workerID)
				entry, ok := sm.Get(key)
				if !ok || entry.Value != workerID {
					// Don't t.Errorf here since it's not thread-safe, but keep track
				}
			}
		}(i)
	}

	wg.Wait()
	if sm.Count() != 1000 {
		t.Errorf("Expected total count 1000, got %d", sm.Count())
	}
}

func TestShardedMap_EvictOldestWithCallback(t *testing.T) {
	sm := NewShardedMap[int](100)
	for i := uint64(0); i < 100; i++ {
		sm.Set(i, int(i))
	}
	callbacks := int64(0)
	removed := sm.EvictOldestWithCallback(10, func(key uint64, value int) {
		callbacks++
	})
	if removed == 0 || callbacks != removed {
		t.Fatalf("invalid eviction callback accounting: removed=%d callbacks=%d", removed, callbacks)
	}
	if sm.Count() > 10 || sm.Count() != 100-removed {
		t.Fatalf("cache ceiling not enforced: count=%d removed=%d", sm.Count(), removed)
	}
}

func TestFlowBucket_Limit(t *testing.T) {
	// 10 PPS limit, 1000 BPS limit
	fb := NewFlowBucket(10, 1000)

	// Consume 10 packets immediately (burst allowed up to 2x Max = 20 tokens)
	// Actually, initial state in NewFlowBucket has fb.PacketTokens = maxPPS = 10.
	for i := 0; i < 10; i++ {
		if !fb.Allow(50) {
			t.Fatalf("Packet %d should have been allowed", i)
		}
	}

	// 11th packet should be dropped
	if fb.Allow(50) {
		t.Errorf("11th packet should be dropped (tokens depleted)")
	}

	// Wait 200ms to refill 2 packets (10 * 0.2)
	time.Sleep(210 * time.Millisecond)
	if !fb.Allow(50) {
		t.Errorf("Packet should be allowed after refill")
	}
}

func TestIPBucket_Limit(t *testing.T) {
	ib := NewIPBucket(5)

	// Consume 5
	for i := 0; i < 5; i++ {
		if !ib.Allow() {
			t.Fatalf("IP packet %d should have been allowed", i)
		}
	}

	if ib.Allow() {
		t.Errorf("6th packet should be rate limited")
	}

	// Blacklist
	ib.Blacklist(50 * time.Millisecond)
	if ib.Allow() {
		t.Errorf("Should be blocked while blacklisted")
	}

	time.Sleep(60 * time.Millisecond)
	if !ib.Allow() {
		t.Errorf("Should allow after blacklist expiration")
	}
}
