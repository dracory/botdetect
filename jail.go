package botdetect

import (
	"sync"
	"time"
)

// jailStore is a small bounded in-memory IP jail. Entries expire lazily
// on read; when the map is full, expired entries are swept and — as a
// last resort — the map is cleared entirely, so a botnet rotating IPs
// can't grow it unbounded. Same strategy as detectionCache.
//
// The store is per-process: jails do not survive restarts and are not
// shared across replicas. That is deliberate — a jail is a short-lived
// cost-saving hint, not a durable banlist.
const jailStoreSize = 10000

type jailStore struct {
	mu      sync.Mutex
	entries map[string]time.Time // ip → jail-until
	ttl     time.Duration
}

func newJailStore(ttl time.Duration) *jailStore {
	return &jailStore{entries: make(map[string]time.Time, 256), ttl: ttl}
}

// jailed reports whether ip is currently jailed. Expired entries are
// evicted on read and treated as free.
func (s *jailStore) jailed(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	until, ok := s.entries[ip]
	if !ok {
		return false
	}
	if time.Now().After(until) {
		delete(s.entries, ip)
		return false
	}
	return true
}

// jail marks ip as jailed for the store's TTL. Re-jailing an already
// jailed IP extends the term from now.
func (s *jailStore) jail(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.entries) >= jailStoreSize {
		now := time.Now()
		for k, until := range s.entries {
			if now.After(until) {
				delete(s.entries, k)
			}
		}
		if len(s.entries) >= jailStoreSize {
			clear(s.entries)
		}
	}
	s.entries[ip] = time.Now().Add(s.ttl)
}
