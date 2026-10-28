package botdetect

import (
	"sync"
	"time"
)

// jailStore is a small bounded in-memory IP jail. Entries expire lazily
// on read; when the map is full, expired entries are swept and — as a
// last resort — a bounded slice is evicted (random map order), so a
// botnet rotating IPs degrades jailing slightly instead of un-jailing
// every offender at once. Same strategy as detectionCache.
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

// jail marks ip as jailed for the store's TTL and reports whether the
// term is new — true on first jailing or after expiry, false when the
// IP was already serving a term. Callers use the bool to fire hooks
// like Options.OnJail exactly once per term; concurrent requests from
// the same IP can't double-report.
func (s *jailStore) jail(ip string) bool {
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
			n := jailStoreSize / 8
			for k := range s.entries {
				delete(s.entries, k)
				if n--; n <= 0 {
					break
				}
			}
		}
	}
	until, ok := s.entries[ip]
	fresh := !ok || time.Now().After(until)
	s.entries[ip] = time.Now().Add(s.ttl)
	return fresh
}
