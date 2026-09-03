// Package datastore provides high-performance concurrent data structures
// for the firewall engine. Optimized for low lock contention on multi-core.
package datastore

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// NumShards is the number of map shards. 64 is optimal for 2-4 core systems.
	NumShards = 64
	shardMask = NumShards - 1
)

// Entry holds a value with TTL tracking
type Entry[V any] struct {
	Value    V
	LastSeen int64 // unix nano
}

// shard is a single partition of the sharded map
type shard[V any] struct {
	mu    sync.RWMutex
	items map[uint64]*Entry[V]
}

// ShardedMap is a concurrent map split into 64 shards to minimize lock contention.
// Key is uint64 (flow key / IP key). Shard = FNV-1a(key) & 0x3F.
type ShardedMap[V any] struct {
	shards   [NumShards]shard[V]
	count    atomic.Int64
	maxItems int
}

// NewShardedMap creates a new sharded map with maxItems limit.
func NewShardedMap[V any](maxItems int) *ShardedMap[V] {
	sm := &ShardedMap[V]{maxItems: maxItems}
	for i := range sm.shards {
		sm.shards[i].items = make(map[uint64]*Entry[V], maxItems/NumShards)
	}
	return sm
}

// getShard returns the shard for a given key using fast bit mixing
func (sm *ShardedMap[V]) getShard(key uint64) *shard[V] {
	// FNV-1a inspired hash mixing for better distribution
	h := key
	h ^= h >> 33
	h *= 0xff51afd7ed558ccd
	h ^= h >> 33
	return &sm.shards[h&shardMask]
}

// Get retrieves a value by key. Returns the value and true if found.
func (sm *ShardedMap[V]) Get(key uint64) (*Entry[V], bool) {
	s := sm.getShard(key)
	s.mu.RLock()
	entry, ok := s.items[key]
	s.mu.RUnlock()
	return entry, ok
}

// GetOrCreate retrieves existing entry or creates a new one with initFn.
// Returns the entry and true if it was newly created.
func (sm *ShardedMap[V]) GetOrCreate(key uint64, initFn func() V) (*Entry[V], bool) {
	s := sm.getShard(key)

	// Fast path: read lock
	s.mu.RLock()
	entry, ok := s.items[key]
	s.mu.RUnlock()
	if ok {
		atomic.StoreInt64(&entry.LastSeen, time.Now().UnixNano())
		return entry, false
	}

	// Slow path: write lock
	s.mu.Lock()
	// Double-check after acquiring write lock
	entry, ok = s.items[key]
	if ok {
		s.mu.Unlock()
		atomic.StoreInt64(&entry.LastSeen, time.Now().UnixNano())
		return entry, false
	}

	now := time.Now().UnixNano()
	entry = &Entry[V]{
		Value:    initFn(),
		LastSeen: now,
	}
	s.items[key] = entry
	s.mu.Unlock()
	sm.count.Add(1)
	return entry, true
}

// Set stores a value at the given key.
func (sm *ShardedMap[V]) Set(key uint64, value V) {
	s := sm.getShard(key)
	now := time.Now().UnixNano()
	s.mu.Lock()
	existing, ok := s.items[key]
	if ok {
		existing.Value = value
		existing.LastSeen = now
	} else {
		s.items[key] = &Entry[V]{Value: value, LastSeen: now}
		sm.count.Add(1)
	}
	s.mu.Unlock()
}

// Touch updates the LastSeen timestamp for a key.
func (sm *ShardedMap[V]) Touch(key uint64) {
	s := sm.getShard(key)
	now := time.Now().UnixNano()
	s.mu.RLock()
	entry, ok := s.items[key]
	s.mu.RUnlock()
	if ok {
		atomic.StoreInt64(&entry.LastSeen, now)
	}
}

// Delete removes a key from the map.
func (sm *ShardedMap[V]) Delete(key uint64) {
	s := sm.getShard(key)
	s.mu.Lock()
	if _, ok := s.items[key]; ok {
		delete(s.items, key)
		sm.count.Add(-1)
	}
	s.mu.Unlock()
}

// Count returns the total number of entries across all shards.
func (sm *ShardedMap[V]) Count() int64 {
	return sm.count.Load()
}

// Sweep removes all entries older than ttl duration.
// Called periodically by the sweeper goroutine.
// Returns number of entries removed.
func (sm *ShardedMap[V]) Sweep(ttl time.Duration) int64 {
	cutoff := time.Now().Add(-ttl).UnixNano()
	var removed int64

	for i := range sm.shards {
		s := &sm.shards[i]
		s.mu.Lock()
		for key, entry := range s.items {
			if atomic.LoadInt64(&entry.LastSeen) < cutoff {
				delete(s.items, key)
				removed++
			}
		}
		s.mu.Unlock()
	}

	sm.count.Add(-removed)
	return removed
}

// SweepWithCallback removes expired entries and calls callback for each.
func (sm *ShardedMap[V]) SweepWithCallback(ttl time.Duration, cb func(key uint64, val V)) int64 {
	cutoff := time.Now().Add(-ttl).UnixNano()
	var removed int64

	for i := range sm.shards {
		s := &sm.shards[i]
		s.mu.Lock()
		for key, entry := range s.items {
			if atomic.LoadInt64(&entry.LastSeen) < cutoff {
				if cb != nil {
					cb(key, entry.Value)
				}
				delete(s.items, key)
				removed++
			}
		}
		s.mu.Unlock()
	}

	sm.count.Add(-removed)
	return removed
}

// EvictOldest removes the OLDEST entries (by LastSeen) when map exceeds maxItems.
// Candidates are ordered globally so uneven shard distribution still reaches
// the requested ceiling.
// Returns number evicted.
func (sm *ShardedMap[V]) EvictOldest(targetSize int) int64 {
	return sm.EvictOldestWithCallback(targetSize, nil)
}

// EvictOldestWithCallback evicts to targetSize and reports each removed item.
func (sm *ShardedMap[V]) EvictOldestWithCallback(targetSize int, cb func(key uint64, val V)) int64 {
	current := sm.count.Load()
	if current <= int64(targetSize) {
		return 0
	}

	toRemove := current - int64(targetSize)
	type candidate struct {
		key      uint64
		lastSeen int64
	}
	candidates := make([]candidate, 0, current)
	for i := range sm.shards {
		s := &sm.shards[i]
		s.mu.RLock()
		for key, entry := range s.items {
			candidates = append(candidates, candidate{key: key, lastSeen: atomic.LoadInt64(&entry.LastSeen)})
		}
		s.mu.RUnlock()
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].lastSeen < candidates[j].lastSeen })

	var removed int64
	for _, item := range candidates {
		if removed >= toRemove {
			break
		}
		s := sm.getShard(item.key)
		s.mu.Lock()
		entry, exists := s.items[item.key]
		if exists {
			delete(s.items, item.key)
		}
		s.mu.Unlock()
		if !exists {
			continue
		}
		if cb != nil {
			cb(item.key, entry.Value)
		}
		removed++
	}

	sm.count.Add(-removed)
	return removed
}

// ForEach iterates over all entries (read-locked per shard).
// The callback should not modify the map.
func (sm *ShardedMap[V]) ForEach(fn func(key uint64, entry *Entry[V]) bool) {
	for i := range sm.shards {
		s := &sm.shards[i]
		s.mu.RLock()
		shouldContinue := true
		for key, entry := range s.items {
			if !fn(key, entry) {
				shouldContinue = false
				break
			}
		}
		s.mu.RUnlock()
		if !shouldContinue {
			break
		}
	}
}
