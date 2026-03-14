package fscache

import (
	"errors"
	"io/fs"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeFileInfo satisfies fs.FileInfo for testing.
type fakeFileInfo struct {
	name string
	size int64
	mode fs.FileMode
}

func (f fakeFileInfo) Name() string       { return f.name }
func (f fakeFileInfo) Size() int64        { return f.size }
func (f fakeFileInfo) Mode() fs.FileMode  { return f.mode }
func (f fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (f fakeFileInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeFileInfo) Sys() any           { return nil }

func TestWrapStatCachesHitAndMiss(t *testing.T) {
	var calls atomic.Int32
	c := New()
	wrapped := c.WrapStat(func(path string) (fs.FileInfo, error) {
		calls.Add(1)
		return fakeFileInfo{name: path}, nil
	})

	info1, err1 := wrapped("/a")
	info2, err2 := wrapped("/a")

	if err1 != nil || err2 != nil {
		t.Fatal("unexpected error")
	}
	if info1.Name() != "/a" || info2.Name() != "/a" {
		t.Fatal("wrong name")
	}
	if calls.Load() != 1 {
		t.Fatalf("expected 1 call, got %d", calls.Load())
	}
}

func TestWrapStatCachesErrors(t *testing.T) {
	var calls atomic.Int32
	c := New()
	wrapped := c.WrapStat(func(_ string) (fs.FileInfo, error) {
		calls.Add(1)
		return nil, fs.ErrNotExist
	})

	_, err1 := wrapped("/missing")
	_, err2 := wrapped("/missing")

	if !errors.Is(err1, fs.ErrNotExist) || !errors.Is(err2, fs.ErrNotExist) {
		t.Fatal("error not cached")
	}
	if calls.Load() != 1 {
		t.Fatalf("expected 1 call, got %d", calls.Load())
	}
}

func TestWrapLstatSeparateFromStat(t *testing.T) {
	c := New()
	stat := c.WrapStat(func(path string) (fs.FileInfo, error) {
		return fakeFileInfo{name: "stat:" + path}, nil
	})
	lstat := c.WrapLstat(func(path string) (fs.FileInfo, error) {
		return fakeFileInfo{name: "lstat:" + path}, nil
	})

	info1, _ := stat("/a")
	info2, _ := lstat("/a")

	if info1.Name() != "stat:/a" {
		t.Fatal("stat returned wrong info")
	}
	if info2.Name() != "lstat:/a" {
		t.Fatal("lstat returned wrong info")
	}
}

func TestWrapLstatCachesHitAndError(t *testing.T) {
	var calls atomic.Int32
	c := New()
	lstat := c.WrapLstat(func(_ string) (fs.FileInfo, error) {
		calls.Add(1)
		return nil, fs.ErrPermission
	})

	_, err1 := lstat("/secret")
	_, err2 := lstat("/secret")

	if !errors.Is(err1, fs.ErrPermission) || !errors.Is(err2, fs.ErrPermission) {
		t.Fatal("error not cached")
	}
	if calls.Load() != 1 {
		t.Fatalf("expected 1 call, got %d", calls.Load())
	}
}

func TestWrapReadFileCachesContents(t *testing.T) {
	var calls atomic.Int32
	c := New()
	read := c.WrapReadFile(func(_ string) ([]byte, error) {
		calls.Add(1)
		return []byte("hello"), nil
	})

	d1, _ := read("/a.txt")
	d2, _ := read("/a.txt")

	if string(d1) != "hello" || string(d2) != "hello" {
		t.Fatal("wrong content")
	}
	if calls.Load() != 1 {
		t.Fatalf("expected 1 call, got %d", calls.Load())
	}
}

func TestWrapReadFileCachesErrors(t *testing.T) {
	var calls atomic.Int32
	c := New()
	read := c.WrapReadFile(func(_ string) ([]byte, error) {
		calls.Add(1)
		return nil, fs.ErrNotExist
	})

	_, err1 := read("/gone")
	_, err2 := read("/gone")

	if !errors.Is(err1, fs.ErrNotExist) || !errors.Is(err2, fs.ErrNotExist) {
		t.Fatal("error not cached")
	}
	if calls.Load() != 1 {
		t.Fatalf("expected 1 call, got %d", calls.Load())
	}
}

func TestWrapGlobCachesResults(t *testing.T) {
	var calls atomic.Int32
	c := New()
	glob := c.WrapGlob(func(_ string) ([]string, error) {
		calls.Add(1)
		return []string{"/a.conf", "/b.conf"}, nil
	})

	p1, _ := glob("/etc/*.conf")
	p2, _ := glob("/etc/*.conf")

	if len(p1) != 2 || len(p2) != 2 {
		t.Fatal("wrong path count")
	}
	if calls.Load() != 1 {
		t.Fatalf("expected 1 call, got %d", calls.Load())
	}
}

func TestWrapGlobCachesErrors(t *testing.T) {
	var calls atomic.Int32
	c := New()
	glob := c.WrapGlob(func(_ string) ([]string, error) {
		calls.Add(1)
		return nil, errors.New("bad pattern")
	})

	_, err1 := glob("[invalid")
	_, err2 := glob("[invalid")

	if err1 == nil || err2 == nil {
		t.Fatal("expected error")
	}
	if calls.Load() != 1 {
		t.Fatalf("expected 1 call, got %d", calls.Load())
	}
}

func TestWrapLookupDistinguishesPrefixes(t *testing.T) {
	var userCalls, groupCalls atomic.Int32
	c := New()
	userLookup := c.WrapLookup("u:", func(uid string) (string, error) {
		userCalls.Add(1)
		return "user_" + uid, nil
	})
	groupLookup := c.WrapLookup("g:", func(gid string) (string, error) {
		groupCalls.Add(1)
		return "group_" + gid, nil
	})

	u1, _ := userLookup("1000")
	u2, _ := userLookup("1000")
	g1, _ := groupLookup("1000")
	g2, _ := groupLookup("1000")

	if u1 != "user_1000" || u2 != "user_1000" {
		t.Fatal("user lookup wrong")
	}
	if g1 != "group_1000" || g2 != "group_1000" {
		t.Fatal("group lookup wrong")
	}
	if userCalls.Load() != 1 {
		t.Fatalf("expected 1 user call, got %d", userCalls.Load())
	}
	if groupCalls.Load() != 1 {
		t.Fatalf("expected 1 group call, got %d", groupCalls.Load())
	}
}

func TestConcurrentStatAccess(t *testing.T) {
	c := New()
	var calls atomic.Int64
	wrapped := c.WrapStat(func(path string) (fs.FileInfo, error) {
		calls.Add(1)
		return fakeFileInfo{name: path}, nil
	})

	var wg sync.WaitGroup
	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 50 {
				_, _ = wrapped("/shared-path")
			}
		}()
	}
	wg.Wait()

	// The fn should be called at most a handful of times (theoretically 1,
	// but goroutine scheduling may cause a few misses before the first write lands).
	if calls.Load() > 100 {
		t.Fatalf("expected far fewer than 5000 calls, got %d", calls.Load())
	}
}
