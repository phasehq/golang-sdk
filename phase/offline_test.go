package phase

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestCacheWriteCreatesFileWithCorrectPerms(t *testing.T) {
	dir := t.TempDir()
	fp := filepath.Join(dir, "subdir", "test.json")

	data := []byte(`{"key":"value"}`)
	if err := cacheWrite(fp, data); err != nil {
		t.Fatalf("cacheWrite failed: %v", err)
	}

	got, err := os.ReadFile(fp)
	if err != nil {
		t.Fatalf("reading written file: %v", err)
	}
	if string(got) != string(data) {
		t.Errorf("content mismatch: got %q, want %q", got, data)
	}

	// Verify parent dir permissions (skip on Windows — permission model differs)
	if os.PathSeparator != '\\' {
		info, _ := os.Stat(filepath.Dir(fp))
		if perm := info.Mode().Perm(); perm != 0700 {
			t.Errorf("parent dir perms: got %o, want 0700", perm)
		}
		finfo, _ := os.Stat(fp)
		if perm := finfo.Mode().Perm(); perm != 0600 {
			t.Errorf("file perms: got %o, want 0600", perm)
		}
	}
}

func TestCacheWriteOverwritesExistingFile(t *testing.T) {
	dir := t.TempDir()
	fp := filepath.Join(dir, "test.json")

	// Write initial content
	if err := cacheWrite(fp, []byte(`{"v":1}`)); err != nil {
		t.Fatalf("initial write: %v", err)
	}

	// Overwrite
	if err := cacheWrite(fp, []byte(`{"v":2}`)); err != nil {
		t.Fatalf("overwrite: %v", err)
	}

	got, _ := os.ReadFile(fp)
	if string(got) != `{"v":2}` {
		t.Errorf("overwrite failed: got %q", got)
	}

	// Verify no leftover .tmp file
	if _, err := os.Stat(fp + ".tmp"); !os.IsNotExist(err) {
		t.Error("leftover .tmp file found after successful write")
	}
}

func TestCacheWriteConcurrent(t *testing.T) {
	dir := t.TempDir()
	fp := filepath.Join(dir, "concurrent.json")

	var wg sync.WaitGroup
	errs := make([]error, 50)

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			data := []byte(fmt.Sprintf(`{"idx":%d}`, idx))
			errs[idx] = cacheWrite(fp, data)
		}(i)
	}
	wg.Wait()

	// All writes should succeed (no corrupt state)
	for i, err := range errs {
		if err != nil {
			t.Errorf("write %d failed: %v", i, err)
		}
	}

	// File should exist and be valid JSON (one of the writes won)
	got, err := os.ReadFile(fp)
	if err != nil {
		t.Fatalf("final read: %v", err)
	}
	if len(got) == 0 {
		t.Error("file is empty after concurrent writes")
	}
}

func TestCacheReadMissingFile(t *testing.T) {
	_, err := cacheRead(filepath.Join(t.TempDir(), "nonexistent.json"))
	if err == nil {
		t.Error("expected error reading nonexistent file")
	}
}

func TestPathHash(t *testing.T) {
	h1 := pathHash("dev", "myapp", "id1", "/")
	h2 := pathHash("dev", "myapp", "id1", "")
	if h1 != h2 {
		t.Error("empty path and '/' should produce the same hash")
	}

	h3 := pathHash("dev", "myapp", "id1", "/backend")
	if h1 == h3 {
		t.Error("different paths should produce different hashes")
	}

	h4 := pathHash("staging", "myapp", "id1", "/")
	if h1 == h4 {
		t.Error("different envs should produce different hashes")
	}
}

func TestSecretsCachePath(t *testing.T) {
	dir := "/tmp/cache"
	p := secretsCachePath(dir, "dev", "myapp", "id1", "/")
	if filepath.Dir(p) != filepath.Join(dir, "secrets") {
		t.Errorf("unexpected parent dir: %s", filepath.Dir(p))
	}
	if filepath.Ext(p) != ".json" {
		t.Errorf("expected .json extension, got %s", filepath.Ext(p))
	}
}
