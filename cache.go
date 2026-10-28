package botdetect

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
)

// detectionCache is a small bounded cache keyed by user-agent string.
// Real traffic is highly repetitive (a handful of browser builds and
// crawler agents account for nearly all requests), so a few thousand
// entries capture virtually every UA a site sees.
//
// Keys are capped by cacheKey so an attacker sending megabyte-sized UA
// strings can't bloat the map. On overflow a bounded slice of entries
// is evicted (map iteration order is randomized, so this is effectively
// random eviction) rather than clearing the whole cache — a hostile
// client rotating unique UAs degrades hit rate slightly instead of
// keeping it permanently cold.
const detectionCacheSize = 2048

// uaCacheKeyMaxLen bounds verbatim cache keys; longer user-agents are
// stored under their SHA-256 digest.
const uaCacheKeyMaxLen = 256

type detectionCache struct {
	mu      sync.RWMutex
	entries map[string]Detection
}

func newDetectionCache() *detectionCache {
	return &detectionCache{entries: make(map[string]Detection, detectionCacheSize)}
}

// cacheKey returns a bounded map key: short user-agents verbatim (the
// common case), longer ones hashed.
func cacheKey(ua string) string {
	if len(ua) <= uaCacheKeyMaxLen {
		return ua
	}
	sum := sha256.Sum256([]byte(ua))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func (c *detectionCache) get(key string) (Detection, bool) {
	c.mu.RLock()
	d, ok := c.entries[key]
	c.mu.RUnlock()
	return d, ok
}

func (c *detectionCache) set(key string, d Detection) {
	c.mu.Lock()
	if len(c.entries) >= detectionCacheSize {
		n := detectionCacheSize / 8
		for k := range c.entries {
			delete(c.entries, k)
			if n--; n <= 0 {
				break
			}
		}
	}
	c.entries[key] = d
	c.mu.Unlock()
}
