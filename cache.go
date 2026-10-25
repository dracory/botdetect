package botdetect

import "sync"

// detectionCache is a small bounded cache keyed by user-agent string.
// Real traffic is highly repetitive (a handful of browser builds and
// crawler agents account for nearly all requests), so a few thousand
// entries capture virtually every UA a site sees.
//
// Full-map reset on overflow keeps eviction trivially correct and caps
// memory — a hostile client sending unique UAs can't grow it unbounded.
const detectionCacheSize = 2048

type detectionCache struct {
	mu      sync.RWMutex
	entries map[string]Detection
}

func newDetectionCache() *detectionCache {
	return &detectionCache{entries: make(map[string]Detection, detectionCacheSize)}
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
		clear(c.entries)
	}
	c.entries[key] = d
	c.mu.Unlock()
}
