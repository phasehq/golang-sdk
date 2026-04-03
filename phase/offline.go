package phase

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// OfflineConfig controls offline caching behavior.
// When set on a Phase instance, encrypted API responses are cached to CacheDir
// and served from cache when the network is unavailable.
type OfflineConfig struct {
	CacheDir string // Root cache directory (e.g. ~/.phase/secrets/offline/{account_id})
	Offline  bool   // When true, skip network entirely and serve from cache
}

// SetOfflineConfig enables offline caching on this Phase instance.
func (p *Phase) SetOfflineConfig(cfg *OfflineConfig) {
	p.offlineConfig = cfg
}

// pathHash returns a filesystem-safe SHA-256 hex digest for a cache key.
func pathHash(envName, appName, appID, path string) string {
	if path == "" {
		path = "/"
	}
	raw := fmt.Sprintf("%s|%s|%s|%s", envName, appName, appID, path)
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

// userDataCachePath returns the path for cached user data (AppKeyResponse).
func userDataCachePath(cacheDir string) string {
	return filepath.Join(cacheDir, "userdata.json")
}

// secretsCachePath returns the path for cached encrypted secrets.
func secretsCachePath(cacheDir, envName, appName, appID, path string) string {
	return filepath.Join(cacheDir, "secrets", pathHash(envName, appName, appID, path)+".json")
}

// cacheWrite atomically writes data to a file with 0600 permissions.
func cacheWrite(fp string, data []byte) error {
	dir := filepath.Dir(fp)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".phase-cache-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	// On Windows, rename fails if the target exists or is momentarily locked by
	// another process (e.g. antivirus, concurrent writer). Remove-then-rename is
	// not atomic, so retry a few times on failure.
	var renameErr error
	for attempts := 0; attempts < 5; attempts++ {
		if runtime.GOOS == "windows" {
			os.Remove(fp)
		}
		renameErr = os.Rename(tmpName, fp)
		if renameErr == nil {
			return nil
		}
		if runtime.GOOS != "windows" {
			break
		}
		time.Sleep(time.Duration(attempts+1) * 10 * time.Millisecond)
	}
	os.Remove(tmpName)
	return renameErr
}

// cacheRead reads a cached file.
func cacheRead(fp string) ([]byte, error) {
	return os.ReadFile(fp)
}

