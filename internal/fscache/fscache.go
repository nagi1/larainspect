// Package fscache provides a per-audit concurrent-safe cache for filesystem
// and identity lookups. A single Cache instance should be created at the
// start of an audit run and discarded when the run completes, ensuring
// evidence never becomes stale across runs.
//
// The cache is safe for concurrent readers and writers. Duplicate work on
// the same key by multiple goroutines is harmless: both will compute the
// same result and one write simply overwrites the other.
package fscache

import (
	"io/fs"
	"sync"
)

// lookupMap is a concurrent-safe cache for a single value type.
// Each map has its own RWMutex so stat, read, glob, and name lookups
// never contend with each other.
type lookupMap[V any] struct {
	mu    sync.RWMutex
	items map[string]cached[V]
}

type cached[V any] struct {
	value V
	err   error
}

// getOrCompute returns a cached result or calls compute on a miss.
func (m *lookupMap[V]) getOrCompute(key string, compute func() (V, error)) (V, error) {
	m.mu.RLock()
	entry, found := m.items[key]
	m.mu.RUnlock()
	if found {
		return entry.value, entry.err
	}

	value, err := compute()
	m.mu.Lock()
	m.items[key] = cached[V]{value: value, err: err}
	m.mu.Unlock()
	return value, err
}

// Cache holds per-audit lookup results for filesystem metadata and
// identity resolution. All methods are safe for concurrent use.
type Cache struct {
	stats  lookupMap[fs.FileInfo]
	lstats lookupMap[fs.FileInfo]
	reads  lookupMap[[]byte]
	globs  lookupMap[[]string]
	names  lookupMap[string]
}

// New returns a ready-to-use Cache.
func New() *Cache {
	return &Cache{
		stats:  lookupMap[fs.FileInfo]{items: make(map[string]cached[fs.FileInfo], 128)},
		lstats: lookupMap[fs.FileInfo]{items: make(map[string]cached[fs.FileInfo], 128)},
		reads:  lookupMap[[]byte]{items: make(map[string]cached[[]byte], 32)},
		globs:  lookupMap[[]string]{items: make(map[string]cached[[]string], 16)},
		names:  lookupMap[string]{items: make(map[string]cached[string], 16)},
	}
}

// WrapStat returns a drop-in replacement for os.Stat that caches results.
func (c *Cache) WrapStat(fn func(string) (fs.FileInfo, error)) func(string) (fs.FileInfo, error) {
	return func(path string) (fs.FileInfo, error) {
		return c.stats.getOrCompute(path, func() (fs.FileInfo, error) { return fn(path) })
	}
}

// WrapLstat returns a drop-in replacement for os.Lstat that caches results.
func (c *Cache) WrapLstat(fn func(string) (fs.FileInfo, error)) func(string) (fs.FileInfo, error) {
	return func(path string) (fs.FileInfo, error) {
		return c.lstats.getOrCompute(path, func() (fs.FileInfo, error) { return fn(path) })
	}
}

// WrapReadFile returns a drop-in replacement for os.ReadFile that caches results.
// Callers must not mutate the returned byte slice.
func (c *Cache) WrapReadFile(fn func(string) ([]byte, error)) func(string) ([]byte, error) {
	return func(path string) ([]byte, error) {
		return c.reads.getOrCompute(path, func() ([]byte, error) { return fn(path) })
	}
}

// WrapGlob returns a drop-in replacement for filepath.Glob that caches results.
func (c *Cache) WrapGlob(fn func(string) ([]string, error)) func(string) ([]string, error) {
	return func(pattern string) ([]string, error) {
		return c.globs.getOrCompute(pattern, func() ([]string, error) { return fn(pattern) })
	}
}

// WrapLookup returns a cached wrapper for user or group name resolution.
// The prefix (e.g. "u:" or "g:") prevents UID/GID collisions.
func (c *Cache) WrapLookup(prefix string, fn func(string) (string, error)) func(string) (string, error) {
	return func(id string) (string, error) {
		return c.names.getOrCompute(prefix+id, func() (string, error) { return fn(id) })
	}
}
